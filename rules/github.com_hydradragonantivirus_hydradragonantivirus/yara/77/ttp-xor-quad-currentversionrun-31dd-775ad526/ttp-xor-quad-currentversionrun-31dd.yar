rule TTP_XOR_QUAD_CurrentVersionRun_31dd {
  strings:
    $key_31dd = { 62 b2 [2] 46 bc [2] 6d 90 [2] 43 b2 [2] 57 a9 [2] 58 b3 [2] 46 ae [2] 44 af [2] 5f a9 [2] 43 ae [2] 5f 81 }

  condition:
    any of them
}