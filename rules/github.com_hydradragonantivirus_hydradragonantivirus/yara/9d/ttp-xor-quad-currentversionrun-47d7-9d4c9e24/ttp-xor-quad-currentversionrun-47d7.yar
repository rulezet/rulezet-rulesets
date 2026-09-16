rule TTP_XOR_QUAD_CurrentVersionRun_47d7 {
  strings:
    $key_47d7 = { 14 b8 [2] 30 b6 [2] 1b 9a [2] 35 b8 [2] 21 a3 [2] 2e b9 [2] 30 a4 [2] 32 a5 [2] 29 a3 [2] 35 a4 [2] 29 8b }

  condition:
    any of them
}