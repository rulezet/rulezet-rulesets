rule TTP_XOR_QUAD_CurrentVersionRun_25e8 {
  strings:
    $key_25e8 = { 76 87 [2] 52 89 [2] 79 a5 [2] 57 87 [2] 43 9c [2] 4c 86 [2] 52 9b [2] 50 9a [2] 4b 9c [2] 57 9b [2] 4b b4 }

  condition:
    any of them
}