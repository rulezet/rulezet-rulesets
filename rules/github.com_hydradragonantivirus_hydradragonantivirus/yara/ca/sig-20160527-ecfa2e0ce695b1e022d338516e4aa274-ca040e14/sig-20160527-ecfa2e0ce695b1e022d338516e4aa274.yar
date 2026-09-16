rule sig_20160527_ecfa2e0ce695b1e022d338516e4aa274 {
  meta:
    description = "datamaliciousorder - file 20160527_ecfa2e0ce695b1e022d338516e4aa274.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "833deb80a035bb2d7c5989ee736b155e35d33e60fee60717a336d7b36e0c2bdc"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<auaNlxcw1.length;i++)if(i%2==0)x.push(auaNlxcw1[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}