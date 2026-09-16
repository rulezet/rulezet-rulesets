rule TTP_XOR_QUAD_CurrentVersionRun_27f4 {
  strings:
    $key_27f4 = { 74 9b [2] 50 95 [2] 7b b9 [2] 55 9b [2] 41 80 [2] 4e 9a [2] 50 87 [2] 52 86 [2] 49 80 [2] 55 87 [2] 49 a8 }

  condition:
    any of them
}