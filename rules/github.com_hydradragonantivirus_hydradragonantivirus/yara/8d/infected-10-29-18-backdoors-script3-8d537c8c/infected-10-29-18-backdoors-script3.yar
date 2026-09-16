rule infected_10_29_18_backdoors_script3 {
  meta:
    description = "backdoors - file script3"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-28"
    hash1       = "c0df9c932cf8d9f4aa097ed4d2990fa1415c1ff061b73c535274e8b75fa85017"

  strings:
    $s1  = "$l1 = '<script src=\"https://hotopponents.site/site.js?wtr=1\" type=\"text/javascript\" async></script>';" fullword ascii
    $s2  = "$a = 'find / -type f -name \"*\" | xargs grep -rl \"<head\"';" fullword ascii
    $s3  = "$t = shell_exec($a);" fullword ascii
    $s4  = "105, 116, 101, 47, 115, 105, 116, 101, 46, 106, 115, 63, 119, 116, 114, 61, 50); s0.parentNode.insertBefore(s1,s0); })();';" fullword ascii
    $s5  = "if (strpos($g, '104, 111, 116, 111, 112, 112, 111, 110, 101, 110') !== false || strpos($g, '0xfcc4') !== false) {" fullword ascii
    $s6  = "$g = file_get_contents($f);" fullword ascii
    $s7  = "$a = 'find / -type f -name \"*jquery*js\" | xargs grep -rl \"var\"';" fullword ascii
    $s8  = "$g = str_replace(\"</head>\",$l1.\"</head>\",$g);" fullword ascii
    $s9  = "$l32 = '(function(){ var s1=document.createElement(\"script\"),s0=document.getElementsByTagName(\"script\")[0]; s1.async=true; s" ascii
    $s10 = "$g = str_replace(\"<head>\",\"<head>\".$l1,$g);" fullword ascii
    $s11 = "if (strpos($g, '104, 111, 116, 111, 112, 112, 111, 110, 101, 110') !== false) {" fullword ascii
    $s12 = "if (strpos($g, 'hotopponents') !== false || strpos($g, '0xfcc4') !== false) {" fullword ascii
    $s13 = "echo \"1e:\".$f;" fullword ascii
    $s14 = "$l32 = '(function(){ var s1=document.createElement(\"script\"),s0=document.getElementsByTagName(\"script\")[0]; s1.async=true; s" ascii
    $s15 = "@file_put_contents($f,$g);" fullword ascii
    $s16 = "echo \"e:\".$f;" fullword ascii

  condition:
    (uint16(0) == 0x6124 and
      filesize < 4KB and
      (8 of them)
    ) or (all of them)
}