rule TTP_XOR_QUAD_CurrentVersionRun_1ee9 {
  strings:
    $key_1ee9 = { 4d 86 [2] 69 88 [2] 42 a4 [2] 6c 86 [2] 78 9d [2] 77 87 [2] 69 9a [2] 6b 9b [2] 70 9d [2] 6c 9a [2] 70 b5 }

  condition:
    any of them
}