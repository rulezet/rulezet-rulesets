rule infected_phishing_ip_range_check {
  meta:
    description = "phishing - file ip_range_check.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "22190ec22232bc1eb79e856b0e5ffe967aeb4b82fe688f1b1e7dcc0939d1c304"

  strings:
    $s1  = "redirectTo(\"Login.php?public/enroll/IdentifyUser-aspx-LOB=RBGLogon&\" . generateRandomString(80));" fullword ascii
    $s2  = "fputs($fp, \"IP: $v_ip - DATE: $v_date - BROWSER: $v_agent\\r\\n\");" fullword ascii
    $s3  = "header(\"Location: https://chaseonline.com/\");" fullword ascii
    $s4  = "$fp = fopen(\"logs/accepted_visitors.txt\", \"a\");" fullword ascii
    $s5  = "$fp = fopen(\"logs/denied_visitors.txt\", \"a\");" fullword ascii
    $s6  = "Created by legzy -- icq: 692561824 " fullword ascii
    $s7  = "require_once(\"includes/functions.php\");" fullword ascii
    $s8  = "$msg = \"PASSED: \".$checklist->message();" fullword ascii
    $s9  = "$msg = \"FAILED: \".$checklist->message();" fullword ascii
    $s10 = "$result = $checklist->ipPass( $ip );" fullword ascii
    $s11 = "$_SESSION['page_a_visited'] = true;" fullword ascii
    $s12 = "# Visitor IP range check" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (8 of them)
    ) or (all of them)
}