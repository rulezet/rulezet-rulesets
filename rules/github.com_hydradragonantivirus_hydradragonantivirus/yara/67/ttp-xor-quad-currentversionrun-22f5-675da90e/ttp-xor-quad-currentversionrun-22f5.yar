rule TTP_XOR_QUAD_CurrentVersionRun_22f5 {
  strings:
    $key_22f5 = { 71 9a [2] 55 94 [2] 7e b8 [2] 50 9a [2] 44 81 [2] 4b 9b [2] 55 86 [2] 57 87 [2] 4c 81 [2] 50 86 [2] 4c a9 }

  condition:
    any of them
}