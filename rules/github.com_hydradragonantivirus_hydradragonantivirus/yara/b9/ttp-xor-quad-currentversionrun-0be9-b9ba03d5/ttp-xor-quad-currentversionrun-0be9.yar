rule TTP_XOR_QUAD_CurrentVersionRun_0be9 {
  strings:
    $key_0be9 = { 58 86 [2] 7c 88 [2] 57 a4 [2] 79 86 [2] 6d 9d [2] 62 87 [2] 7c 9a [2] 7e 9b [2] 65 9d [2] 79 9a [2] 65 b5 }

  condition:
    any of them
}