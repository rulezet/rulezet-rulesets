rule TTP_XOR_QUAD_CurrentVersionRun_77d6 {
  strings:
    $key_77d6 = { 24 b9 [2] 00 b7 [2] 2b 9b [2] 05 b9 [2] 11 a2 [2] 1e b8 [2] 00 a5 [2] 02 a4 [2] 19 a2 [2] 05 a5 [2] 19 8a }

  condition:
    any of them
}