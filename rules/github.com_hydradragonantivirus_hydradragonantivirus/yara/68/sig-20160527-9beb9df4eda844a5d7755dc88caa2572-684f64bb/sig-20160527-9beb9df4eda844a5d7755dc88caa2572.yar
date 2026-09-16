rule sig_20160527_9beb9df4eda844a5d7755dc88caa2572 {
  meta:
    description = "datamaliciousorder - file 20160527_9beb9df4eda844a5d7755dc88caa2572.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4e5c01b5f33d7109cbd4602439930f0027d4013b826740a96e976d728151c56"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a1UtU3q3doO.length;i++)if(i%2==0)x.push(a1UtU3q3doO[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}