rule TTP_XOR_QUAD_CurrentVersionRun_65f4 {
  strings:
    $key_65f4 = { 36 9b [2] 12 95 [2] 39 b9 [2] 17 9b [2] 03 80 [2] 0c 9a [2] 12 87 [2] 10 86 [2] 0b 80 [2] 17 87 [2] 0b a8 }

  condition:
    any of them
}