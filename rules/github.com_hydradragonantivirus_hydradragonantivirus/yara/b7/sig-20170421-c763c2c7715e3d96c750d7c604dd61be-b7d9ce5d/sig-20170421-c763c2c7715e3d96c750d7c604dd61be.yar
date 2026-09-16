rule sig_20170421_c763c2c7715e3d96c750d7c604dd61be {
  meta:
    description = "datamaliciousorder - file 20170421_c763c2c7715e3d96c750d7c604dd61be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c773865753774e32263e292384dfad7270328abd946d89c1e926108a24ef0239"

  strings:
    $s1 = "var rima = 10 * 50;" fullword ascii
    $s2 = "function ataaa(ziyter) {eval(ziyter);}" fullword ascii
    $s3 = "function muhter(kjg, lki) {return kjg.split(lki);}" fullword ascii
    $s4 = "function grohot(hunko,b1,b2,b3) {hunko.open(b1, b2, b3);}" fullword ascii
    $s5 = "var uuu = 0;while(uuu<999999) {uuu++;}" fullword ascii
    $s6 = "function fuuu(fuu1, fuu2) {return fuu1.join(fuu2);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}