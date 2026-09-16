rule TTP_XOR_QUAD_CurrentVersionRun_67f4 {
  strings:
    $key_67f4 = { 34 9b [2] 10 95 [2] 3b b9 [2] 15 9b [2] 01 80 [2] 0e 9a [2] 10 87 [2] 12 86 [2] 09 80 [2] 15 87 [2] 09 a8 }

  condition:
    any of them
}