rule TTP_XOR_QUAD_CurrentVersionRun_40d6 {
  strings:
    $key_40d6 = { 13 b9 [2] 37 b7 [2] 1c 9b [2] 32 b9 [2] 26 a2 [2] 29 b8 [2] 37 a5 [2] 35 a4 [2] 2e a2 [2] 32 a5 [2] 2e 8a }

  condition:
    any of them
}