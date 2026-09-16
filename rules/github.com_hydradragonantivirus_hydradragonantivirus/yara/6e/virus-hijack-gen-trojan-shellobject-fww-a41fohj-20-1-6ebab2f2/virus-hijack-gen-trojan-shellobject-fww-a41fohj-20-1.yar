rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_20_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f13ddc9117be677aa7f3c8ca1f12b3f8f93373c9eccb01243a48e3d2782eb4c5"

  strings:
    $s1  = "sc.exe create %s binpath= \"%s internal_start\" DisplayName= %s start= auto" fullword ascii
    $s2  = "sc.exe delete %s" fullword ascii
    $s3  = "Mozilla/5.0 (Windows; U; Windows NT 5.2) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13" fullword ascii
    $s4  = "Mozilla/5.0 (Windows; U; Windows NT 5.2) AppleWebKit/525.13 (KHTML, like Gecko) Version/3.1 Safari/525.13" fullword ascii
    $s5  = "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT)" fullword ascii
    $s6  = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2)" fullword ascii
    $s7  = "from a native constructor or from DllMain." fullword ascii
    $s8  = "net start %s" fullword ascii
    $s9  = "send to len: %d<<" fullword ascii
    $s10 = "Fast dec2" fullword ascii
    $s11 = "invalid map/K\\" fullword ascii
    $s12 = "net stop %s" fullword ascii
    $s13 = "or closure'" fullword ascii
    $s14 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compile" fullword ascii
    $s15 = "Accept: application/x-ms-application, image/jpeg, application/xaml+xml, image/gif, image/pjpeg, application/x-ms-xbap, applicati" ascii
    $s16 = "Accept: application/x-ms-application, image/jpeg, application/xaml+xml, image/gif, image/pjpeg, application/x-ms-xbap, applicati" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}