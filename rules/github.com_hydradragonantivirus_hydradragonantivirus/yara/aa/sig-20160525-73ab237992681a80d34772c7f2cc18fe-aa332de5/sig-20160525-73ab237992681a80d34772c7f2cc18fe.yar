rule sig_20160525_73ab237992681a80d34772c7f2cc18fe {
  meta:
    description = "datamaliciousorder - file 20160525_73ab237992681a80d34772c7f2cc18fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b5196275d40bcd2229d185fe22a48015428b43033aa5bc1e2466d8823c804d5"

  strings:
    $s1 = "dare + me+dnenoisilloce+)eixode(gsme + imd+)tsilslianbmuhtod(cthd + ssorcad + sdnetd+modnard + ecapsetihwxelfd+md + )dnenoisillo" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}