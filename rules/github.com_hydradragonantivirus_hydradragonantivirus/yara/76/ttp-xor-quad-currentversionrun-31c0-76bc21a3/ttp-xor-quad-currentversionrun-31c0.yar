rule TTP_XOR_QUAD_CurrentVersionRun_31c0 {
  strings:
    $key_31c0 = { 62 af [2] 46 a1 [2] 6d 8d [2] 43 af [2] 57 b4 [2] 58 ae [2] 46 b3 [2] 44 b2 [2] 5f b4 [2] 43 b3 [2] 5f 9c }

  condition:
    any of them
}