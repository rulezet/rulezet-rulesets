rule sig_20160527_4a4b7b788eca577f8ffd52fb16f23264 {
  meta:
    description = "datamaliciousorder - file 20160527_4a4b7b788eca577f8ffd52fb16f23264.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a58e2791ed5619a4076c34a8889404083c737ec2b21ee2f5f63f8eb9ec7afd32"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<axDiYLw0O.length;i++)if(i%2==0)x.push(axDiYLw0O[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}