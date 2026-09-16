rule sig_20160527_b23421a8f2c12f613213c61071aee9ed {
  meta:
    description = "datamaliciousorder - file 20160527_b23421a8f2c12f613213c61071aee9ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07b2819cac38b6526527c9f446c96b947095f3b1ef9c5f91a90ae3b02b8b0a68"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<abdgHa1sgC.length;i++)if(i%2==0)x.push(abdgHa1sgC[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}