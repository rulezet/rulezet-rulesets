rule TTP_XOR_QUAD_CurrentVersionRun_07f4 {
  strings:
    $key_07f4 = { 54 9b [2] 70 95 [2] 5b b9 [2] 75 9b [2] 61 80 [2] 6e 9a [2] 70 87 [2] 72 86 [2] 69 80 [2] 75 87 [2] 69 a8 }

  condition:
    any of them
}