rule sig_20160527_74b7d33381c238c162b7deadd0184931 {
  meta:
    description = "datamaliciousorder - file 20160527_74b7d33381c238c162b7deadd0184931.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25078a28b3b461bff19b3625c150d692061d903f65d1652f208e81abfcb219ae"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aQa5oP07.length;i++)if(i%2==0)x.push(aQa5oP07[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}