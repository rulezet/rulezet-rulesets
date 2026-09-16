rule TTP_XOR_QUAD_CurrentVersionRun_c8db {
  strings:
    $key_c8db = { 9b b4 [2] bf ba [2] 94 96 [2] ba b4 [2] ae af [2] a1 b5 [2] bf a8 [2] bd a9 [2] a6 af [2] ba a8 [2] a6 87 }

  condition:
    any of them
}