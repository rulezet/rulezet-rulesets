rule TTP_XOR_QUAD_CurrentVersionRun_cdbd {
  strings:
    $key_cdbd = { 9e d2 [2] ba dc [2] 91 f0 [2] bf d2 [2] ab c9 [2] a4 d3 [2] ba ce [2] b8 cf [2] a3 c9 [2] bf ce [2] a3 e1 }

  condition:
    any of them
}