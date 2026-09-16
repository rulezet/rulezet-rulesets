rule TTP_XOR_QUAD_CurrentVersionRun_71dd {
  strings:
    $key_71dd = { 22 b2 [2] 06 bc [2] 2d 90 [2] 03 b2 [2] 17 a9 [2] 18 b3 [2] 06 ae [2] 04 af [2] 1f a9 [2] 03 ae [2] 1f 81 }

  condition:
    any of them
}