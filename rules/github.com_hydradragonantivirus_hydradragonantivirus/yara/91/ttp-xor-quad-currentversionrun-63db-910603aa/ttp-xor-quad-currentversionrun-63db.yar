rule TTP_XOR_QUAD_CurrentVersionRun_63db {
  strings:
    $key_63db = { 30 b4 [2] 14 ba [2] 3f 96 [2] 11 b4 [2] 05 af [2] 0a b5 [2] 14 a8 [2] 16 a9 [2] 0d af [2] 11 a8 [2] 0d 87 }

  condition:
    any of them
}