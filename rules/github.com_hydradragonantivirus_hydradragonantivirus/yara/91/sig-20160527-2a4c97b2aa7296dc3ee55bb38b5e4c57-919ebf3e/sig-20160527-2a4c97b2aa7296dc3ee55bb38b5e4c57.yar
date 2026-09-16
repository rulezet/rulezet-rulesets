rule sig_20160527_2a4c97b2aa7296dc3ee55bb38b5e4c57 {
  meta:
    description = "datamaliciousorder - file 20160527_2a4c97b2aa7296dc3ee55bb38b5e4c57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61f45858e82768fb5f32d5f473d3205c93b2a9f8f07ed54456cd078b1e7e47ae"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aWaHo44L1.length;i++)if(i%2==0)x.push(aWaHo44L1[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}