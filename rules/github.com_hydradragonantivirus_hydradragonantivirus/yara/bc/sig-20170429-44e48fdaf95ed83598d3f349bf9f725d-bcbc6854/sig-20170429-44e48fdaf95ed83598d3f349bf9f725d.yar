rule sig_20170429_44e48fdaf95ed83598d3f349bf9f725d {
  meta:
    description = "datamaliciousorder - file 20170429_44e48fdaf95ed83598d3f349bf9f725d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13e9f492095bed1e72f2f59c739e7c11af1818e1170f1bd37641bb8212d68a8e"

  strings:
    $s1 = "function hMqkfolYFKSTyWBO(AWRTernGHhImUly, MIhBraSbeguiCEU, ECDyrmKkSLabtlIx) { " fullword ascii
    $s2 = "if (kltwdeRjYyuvBDhcC() == false) {" fullword ascii
    $s3 = "return AWRTernGHhImUly.split(MIhBraSbeguiCEU).join(ECDyrmKkSLabtlIx); }" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}