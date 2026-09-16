rule TTP_XOR_QUAD_CurrentVersionRun_31f4 {
  strings:
    $key_31f4 = { 62 9b [2] 46 95 [2] 6d b9 [2] 43 9b [2] 57 80 [2] 58 9a [2] 46 87 [2] 44 86 [2] 5f 80 [2] 43 87 [2] 5f a8 }

  condition:
    any of them
}