import "pe"
rule textboxNameNamespace_2 {
  meta:
    description = "4485 - file textboxNameNamespace.jpg"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-07-13"
    hash1       = "010f52eda70eb9ff453e3af6f3d9d20cbda0c4075feb49c209ca1c250c676775"

  strings:
    $s1  = "uwunhkqlzle.dll" fullword ascii
    $s2  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s3  = "operator co_await" fullword ascii
    $s4  = "ggeaxcx" fullword ascii
    $s5  = "wttfzwz" fullword ascii
    $s6  = "fefewzydtdu" fullword ascii
    $s7  = "ilaeemjyjwzjwj" fullword ascii
    $s8  = "enhzmqryc" fullword ascii
    $s9  = "flchfonfpzcwyrg" fullword ascii
    $s10 = "dayhcsokc" fullword ascii
    $s11 = "mtqnlfpbxghmlupsn" fullword ascii
    $s12 = "zqeoctx" fullword ascii
    $s13 = "ryntfydpykrdcftxx" fullword ascii
    $s14 = "atxvtwd" fullword ascii
    $s15 = "icjshmfrldy" fullword ascii
    $s16 = "lenkuktrncmxiafgl" fullword ascii
    $s17 = "alshaswlqmhptxpc" fullword ascii
    $s18 = "izonphi" fullword ascii
    $s19 = "atttyokowqnj" fullword ascii
    $s20 = "nwvohpazb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and
    (pe.imphash() == "4d46e641e0220fb18198a7e15fa6f49f" and (pe.exports("PluginInit") and pe.exports("alshaswlqmhptxpc") and pe.exports("amgqilvxdufvpdbwb") and pe.exports("atttyokowqnj") and pe.exports("atxvtwd") and pe.exports("ayawgsgkusfjmq")) or 8 of them)
}