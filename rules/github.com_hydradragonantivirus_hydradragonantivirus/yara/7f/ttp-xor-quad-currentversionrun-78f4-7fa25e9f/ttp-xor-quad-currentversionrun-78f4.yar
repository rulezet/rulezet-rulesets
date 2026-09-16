rule TTP_XOR_QUAD_CurrentVersionRun_78f4 {
  strings:
    $key_78f4 = { 2b 9b [2] 0f 95 [2] 24 b9 [2] 0a 9b [2] 1e 80 [2] 11 9a [2] 0f 87 [2] 0d 86 [2] 16 80 [2] 0a 87 [2] 16 a8 }

  condition:
    any of them
}