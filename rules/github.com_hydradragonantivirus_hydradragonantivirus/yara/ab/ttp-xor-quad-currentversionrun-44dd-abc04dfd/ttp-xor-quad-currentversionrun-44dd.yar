rule TTP_XOR_QUAD_CurrentVersionRun_44dd {
  strings:
    $key_44dd = { 17 b2 [2] 33 bc [2] 18 90 [2] 36 b2 [2] 22 a9 [2] 2d b3 [2] 33 ae [2] 31 af [2] 2a a9 [2] 36 ae [2] 2a 81 }

  condition:
    any of them
}