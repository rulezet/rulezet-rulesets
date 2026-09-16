rule TTP_XOR_QUAD_CurrentVersionRun_46f4 {
  strings:
    $key_46f4 = { 15 9b [2] 31 95 [2] 1a b9 [2] 34 9b [2] 20 80 [2] 2f 9a [2] 31 87 [2] 33 86 [2] 28 80 [2] 34 87 [2] 28 a8 }

  condition:
    any of them
}