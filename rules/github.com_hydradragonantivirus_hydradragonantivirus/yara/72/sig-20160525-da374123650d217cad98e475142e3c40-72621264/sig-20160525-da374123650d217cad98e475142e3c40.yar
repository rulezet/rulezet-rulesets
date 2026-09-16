rule sig_20160525_da374123650d217cad98e475142e3c40 {
  meta:
    description = "datamaliciousorder - file 20160525_da374123650d217cad98e475142e3c40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "896131394ec6adc5b2a88c41f3be26cf43c32770bd62b5ecc17df2574f1f1382"

  strings:
    $s1 = "nbmuhtos = ims rav;\"qhL\" = tsilslianbmuhtos rav\\n;\"tgn56x\\\\l\" = eixodt rav\\n;\"86x\\\\\" = gsmt rav'[\"split\"]('')[\"re" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}