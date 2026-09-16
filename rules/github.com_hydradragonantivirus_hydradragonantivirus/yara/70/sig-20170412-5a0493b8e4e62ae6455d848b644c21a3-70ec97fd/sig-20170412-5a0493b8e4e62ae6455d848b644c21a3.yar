rule sig_20170412_5a0493b8e4e62ae6455d848b644c21a3 {
  meta:
    description = "datamaliciousorder - file 20170412_5a0493b8e4e62ae6455d848b644c21a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39d17b3b36a11ff4bf2a02430e98a8ac4ab2a4f51e02c8031cf46c45f0644933"

  strings:
    $s1 = "var rima = 500;" fullword ascii
    $s2 = "function ataaa(ziyter) {eval(ziyter);}" fullword ascii
    $s3 = "function muhter(kjg, lki) {return kjg.split(lki);}" fullword ascii
    $s4 = "function grohot(hunko,b1,b2,b3) {hunko.open(b1, b2, b3);}" fullword ascii
    $s5 = "var uuu = 0;while(uuu<999999) {uuu++;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}