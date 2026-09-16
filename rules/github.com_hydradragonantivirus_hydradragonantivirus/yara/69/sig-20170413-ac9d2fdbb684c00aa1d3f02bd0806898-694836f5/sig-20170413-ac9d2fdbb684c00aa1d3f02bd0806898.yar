rule sig_20170413_ac9d2fdbb684c00aa1d3f02bd0806898 {
  meta:
    description = "datamaliciousorder - file 20170413_ac9d2fdbb684c00aa1d3f02bd0806898.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a9e9eaa48b94c587e7ed6d9e64f882085363ac7b78eaf5d6e6c013d2fbb828e"

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