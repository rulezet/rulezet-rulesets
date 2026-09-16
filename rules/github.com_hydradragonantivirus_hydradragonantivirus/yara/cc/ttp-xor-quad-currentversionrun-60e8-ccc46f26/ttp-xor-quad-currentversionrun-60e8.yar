rule TTP_XOR_QUAD_CurrentVersionRun_60e8 {
  strings:
    $key_60e8 = { 33 87 [2] 17 89 [2] 3c a5 [2] 12 87 [2] 06 9c [2] 09 86 [2] 17 9b [2] 15 9a [2] 0e 9c [2] 12 9b [2] 0e b4 }

  condition:
    any of them
}