rule TTP_XOR_QUAD_CurrentVersionRun_0be8 {
  strings:
    $key_0be8 = { 58 87 [2] 7c 89 [2] 57 a5 [2] 79 87 [2] 6d 9c [2] 62 86 [2] 7c 9b [2] 7e 9a [2] 65 9c [2] 79 9b [2] 65 b4 }

  condition:
    any of them
}