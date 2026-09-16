rule TTP_XOR_QUAD_CurrentVersionRun_1ef4 {
  strings:
    $key_1ef4 = { 4d 9b [2] 69 95 [2] 42 b9 [2] 6c 9b [2] 78 80 [2] 77 9a [2] 69 87 [2] 6b 86 [2] 70 80 [2] 6c 87 [2] 70 a8 }

  condition:
    any of them
}