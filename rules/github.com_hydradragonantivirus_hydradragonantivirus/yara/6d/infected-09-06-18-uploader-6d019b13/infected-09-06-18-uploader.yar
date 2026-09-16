rule infected_09_06_18_uploader {
  meta:
    description = "shell2 - file uploader.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-06"
    hash1       = "424f60bd48855ad393b4aa53004f9ab0b33dfa35b753562df5300a086f1a469a"

  strings:
    $s1  = "if((time() - $start_time) > MAX_EXEC_TIME) {" fullword ascii
    $s2  = "if(strpos($file, 'wp-content') === false && strpos($file, 'wp-admin') === false && strpos($file, 'wp-includes') === false) {" fullword ascii
    $s3  = "ZWV0ZWxsYWZyaWVuZC5jb20vdGVsbC8/dXJsPVwnLiR0YWZfcGVybWxpbmsuXCcmdGl0bGU9XCcuJHRhZl90aXRsZS5cJyIgb25jbGljaz0id2luZG93Lm9wZW4oXCdo" ascii  
    $s4  = "cz0wLHNjcmVlblg9MjEwLHNjcmVlblk9MTAwLGxlZnQ9MjEwLHRvcD0xMDBcJyk7IHJldHVybiBmYWxzZTsiIHRhcmdldD0iX2JsYW5rIiB0aXRsZT0iU2hhcmUgVGhp" ascii  
    $s5  = "cyBQb3N0Ij48aW1nIHNyYz0iXCcuJHRhZl9pbWcuXCciIHN0eWxlPSJ3aWR0aDoxMjdweDtoZWlnaHQ6MTZweDtib3JkZXI6MHB4OyIgYWx0PSJTaGFyZSBUaGlzIFBv" ascii  
    $s6  = "ZXRob2Q9InBvc3QiIGVuY3R5cGU9Im11bHRpcGFydC9mb3JtLWRhdGEiPjxpbnB1dCB0eXBlPSJmaWxlIiBuYW1lPSJteV9maWxlIj48aW5wdXQgdHlwZT0ic3VibWl0" ascii  
    $s7  = "c2NyaXB0aW9uOiBBZGRzIGEgXCdTaGFyZSBUaGlzIFBvc3RcJyBidXR0b24gYWZ0ZXIgZWFjaCBwb3N0LiBUaGUgc2VydmljZSB3aGljaCBpcyB1c2VkIGlzIGZyZWV0" ascii  
    $s8  = "RVsncGFzc3dvcmQnXSkgJiYgZW1wdHkoJF9QT1NUWydwYXNzd29yZCddKSkgfHwgKCFlbXB0eSgkX1BPU1RbJ3Bhc3N3b3JkJ10pICYmIG1kNSgkX1BPU1RbJ3Bhc3N3" ascii  
    $s9  = "U0VMRiddLic/Jy4kX1NFUlZFUlsnUVVFUllfU1RSSU5HJ10uJyI+UGFzc3dvcmQgOiA8aW5wdXQgdHlwZT0idGV4dCIgbmFtZT0icGFzc3dvcmQiPjxpbnB1dCB0eXBl" ascii  
    $s10 = "bGFmcmllbmRcJywgXCdzY3JvbGxiYXJzPTEsbWVudWJhcj0wLHdpZHRoPTYxNyxoZWlnaHQ9NTMwLHJlc2l6YWJsZT0xLHRvb2xiYXI9MCxsb2NhdGlvbj0wLHN0YXR1" ascii  
    $s11 = "T00gI19fY29udGVudCBXSEVSRSAxPTEgeyRjb25kfSBPUkRFUiBCWSBgdGl0bGVgIExJTUlUIHskb2Zmc2V0fSwgJGFydGljbGVzX251bSAiOyAvLyBwcmVwYXJlIHF1" ascii  
    $s12 = "dHRwczovL3d3dy5mcmVldGVsbGFmcmllbmQuY29tL3RlbGwvP3VybD1cJy4kdGFmX3Blcm1saW5rLlwnJnRpdGxlPVwnLiR0YWZfdGl0bGUuXCdcJywgXCdmcmVldGVs" ascii  
    $s13 = "cm0gbWV0aG9kPVwicG9zdFwiIGVuY3R5cGU9XCJtdWx0aXBhcnQvZm9ybS1kYXRhXCIgYWN0aW9uPVwieyRfU0VSVkVSWydQSFBfU0VMRiddfVwiPjxpbnB1dCB0eXBl" ascii  
    $s14 = "ZW1wdHkoJF9SRVFVRVNUWyd1c2VyX25hbWUnXSkgJiYgIWVtcHR5KCRfUkVRVUVTVFsndXNlcl9wYXNzd29yZCddKSAmJiAhZW1wdHkoJF9SRVFVRVNUWyd1c2VyX2Vt" ascii  
    $s15 = "cnJheV90b19qc29uKGdldF9mdWxsX3BhdGgoSlVSSTo6YmFzZSgpIC4gJ2luZGV4LnBocD9vcHRpb249Y29tX2NvbnRlbnQmdmlldz1hcnRpY2xlJmlkPScgLiAkX1JF" ascii  
    $s16 = "touch($file_name, time() - rand(60*60*24, 60*60*24*800));" fullword ascii
    $s17 = "if($site_root_dir_splitted[count($site_root_dir_splitted)-1] == $web_dir_splitted[1]) {" fullword ascii
    $s18 = "if(strpos($file, \"wp-config.php\") !== false) {" fullword ascii
    $s19 = "if(strpos($file, \"configuration.php\") !== false) {" fullword ascii
    $s20 = "$file_name = get_file_name($all_dirs[$chosen_dir_index] . '/');" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 100KB and
      (8 of them)
    ) or (all of them)
}