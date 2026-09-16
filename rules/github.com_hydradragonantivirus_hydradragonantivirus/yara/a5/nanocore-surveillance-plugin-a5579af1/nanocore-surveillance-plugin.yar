import "pe"
rule nanocore_surveillance_plugin {
  meta:
    author = "jeFF0Falltrades"

  strings:
    $str_name      = "SurveillanceExClientPlugin.dll" wide ascii
    $str_keylog    = "KeyboardLogging" wide ascii
    $str_dns_log   = "DNSLogging" wide ascii
    $str_html_1    = "<td bgcolor=#FFFFF0 nowrap>.+?<td bgcolor=#FFFCF0 nowrap>(.+?)<td bgcolor=#FFFAF0 nowrap>(.+?)<td bgcolor=#FFF7F0 nowrap>.+?<td bgcolor=#FFF5F0 nowrap>.+?<td bgcolor=#FFF2F0 nowrap>.+?<td bgcolor=#FFF0F0 nowrap>.+?<td bgcolor=#FCF0F2 nowrap>.+?<td bgcolor=#FAF0F5 nowrap>(.+?)<td bgcolor=#F7F0F7 nowrap>" wide ascii
    $str_html_2    = "<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>" wide ascii
    $str_html_3    = "/shtml \"{0}\"" wide ascii
    $str_rsrc_lzma = "Lzma" wide ascii
    $str_nano      = "NanoCore.ClientPlugin" wide ascii
    $str_pass_tool = "ExecutePasswordTool" wide ascii
    $get_raw_input = { 20 03 00 00 10 12 02 12 04 02 7B 09 00 00 04 28 C8 00 00 06 }      $get_dns_cache = { 12 02 7B 62 00 00 04 7E 7F 00 00 0A 28 80 00 00 0A 2C B5 }  
  condition:
    (all of ($get_*)) or (3 of ($str_*)) or (pe.timestamp == 1424566189)
}