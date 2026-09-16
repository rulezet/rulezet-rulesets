import "pe"
rule case_19530_CS_beacon {
  meta:
    description = "file 5d78365.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/"
    date        = "2024-02-18"
    hash1       = "aad75498679aada9ee2179a8824291e3b4781d5683c2fa5b3ec92267ce4a4a33"

  strings:
    $s1  = "%c%c%c%c%c%c%c%c%cnetsvc\\%d" fullword ascii
    $s2  = "WinHttpSvc" fullword ascii
    $s3  = "+  cl_+" fullword ascii
    $s4  = "lsxkrb" fullword ascii
    $s5  = "vDqPSzK6" fullword ascii
    $s6  = ":b(l%h%" fullword ascii
    $s7  = "lszkrb" fullword ascii
    $s8  = "10.0.19041.1266 (WinBuild.160101.0800)" fullword wide
    $s9  = "sMgJkl?sW" fullword ascii
    $s10 = "@}0.Fpn" fullword ascii
    $s11 = "dwPS@%oNB" fullword ascii
    $s12 = "RRcB(jE" fullword ascii
    $s13 = "Rwco)pS" fullword ascii
    $s14 = "cxjI6NB" fullword ascii
    $s15 = "rgNg(>P" fullword ascii
    $s16 = "jawXX_3" fullword ascii
    $s17 = "xSsckrb" fullword ascii
    $s18 = "{uaNB,Pe|K" fullword ascii
    $s19 = "DwcR+dS" fullword ascii
    $s20 = "YwcH*gC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 800KB and
    (pe.imphash() == "49145e436aa571021bb1c7b727f8b049" or 8 of them)
}