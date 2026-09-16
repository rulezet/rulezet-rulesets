rule TTP_XOR_QUAD_CurrentVersionRun_57f4 {
  strings:
    $key_57f4 = { 04 9b [2] 20 95 [2] 0b b9 [2] 25 9b [2] 31 80 [2] 3e 9a [2] 20 87 [2] 22 86 [2] 39 80 [2] 25 87 [2] 39 a8 }

  condition:
    any of them
}