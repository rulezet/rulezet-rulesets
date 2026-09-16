rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_16_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_16_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ac076083b1a9b0855f719fc6aee7b3f9624c79b71561ddaf958813d8a4de591"

  strings:
    $s1  = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; EmbeddedWB 14.52 from: http://www.bsalsa.com/ EmbeddedWB 14.52)" fullword wide
    $s2  = "address:\"" fullword wide
    $s3  = "\"Mozilla/4.0 (compatible; MSIE 5.5)" fullword ascii
    $s4  = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0)" fullword wide
    $s5  = "<A target" fullword wide
    $s6  = "utmcmd=(none); pop_cnt=done; popup_lin=done; bbs_popup=done; __utmb=182435622.16.10.1337607655; _EXEN=1; popup_popall=done; " fullword ascii
    $s7  = "__utma=182435622.1041320105.1337596033.1337602075.1337607655.3; __utmz=182435622.1337596033.1.1.utmcsr=(direct)|utmccn=(direct)|" ascii
    $s8  = "Error loading picture " fullword wide
    $s9  = "GDI+ Module" fullword wide
    $s10 = "__utma=182435622.1041320105.1337596033.1337602075.1337607655.3; __utmz=182435622.1337596033.1.1.utmcsr=(direct)|utmccn=(direct)|" ascii
    $s11 = "eplace(Replace(Replace(RP" fullword ascii
    $s12 = "eplace(Replace(Replace(ReplaVB5!" fullword ascii
    $s13 = "funny value='" fullword wide
    $s14 = "talking&number=" fullword wide
    $s15 = "<input type=\"hidden\" value=\"" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}