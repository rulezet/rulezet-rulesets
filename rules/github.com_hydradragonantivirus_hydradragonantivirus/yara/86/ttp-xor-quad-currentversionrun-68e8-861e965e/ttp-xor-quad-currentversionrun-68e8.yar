rule TTP_XOR_QUAD_CurrentVersionRun_68e8 {
  strings:
    $key_68e8 = { 3b 87 [2] 1f 89 [2] 34 a5 [2] 1a 87 [2] 0e 9c [2] 01 86 [2] 1f 9b [2] 1d 9a [2] 06 9c [2] 1a 9b [2] 06 b4 }

  condition:
    any of them
}