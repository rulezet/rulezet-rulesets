rule TTP_XOR_QUAD_CurrentVersionRun_1ce8 {
  strings:
    $key_1ce8 = { 4f 87 [2] 6b 89 [2] 40 a5 [2] 6e 87 [2] 7a 9c [2] 75 86 [2] 6b 9b [2] 69 9a [2] 72 9c [2] 6e 9b [2] 72 b4 }

  condition:
    any of them
}