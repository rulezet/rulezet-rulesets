rule sig_20160527_ec3c4e86a7c2788b148d8f30f95fc01b {
  meta:
    description = "datamaliciousorder - file 20160527_ec3c4e86a7c2788b148d8f30f95fc01b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbcb48b47a294d313cd67ace4fef177a36239af24d2cf8938ccc930ea84526e"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<akeuzc.length;i++)if(i%2==0)x.push(akeuzc[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}