rule TTP_XOR_QUAD_CurrentVersionRun_40c7 {
  strings:
    $key_40c7 = { 13 a8 [2] 37 a6 [2] 1c 8a [2] 32 a8 [2] 26 b3 [2] 29 a9 [2] 37 b4 [2] 35 b5 [2] 2e b3 [2] 32 b4 [2] 2e 9b }

  condition:
    any of them
}