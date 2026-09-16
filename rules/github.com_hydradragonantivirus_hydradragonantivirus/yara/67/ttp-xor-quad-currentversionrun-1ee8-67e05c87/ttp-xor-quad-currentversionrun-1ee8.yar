rule TTP_XOR_QUAD_CurrentVersionRun_1ee8 {
  strings:
    $key_1ee8 = { 4d 87 [2] 69 89 [2] 42 a5 [2] 6c 87 [2] 78 9c [2] 77 86 [2] 69 9b [2] 6b 9a [2] 70 9c [2] 6c 9b [2] 70 b4 }

  condition:
    any of them
}