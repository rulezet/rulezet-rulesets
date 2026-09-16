rule TTP_XOR_QUAD_CurrentVersionRun_3666 {
  strings:
    $key_3666 = { 65 09 [2] 41 07 [2] 6a 2b [2] 44 09 [2] 50 12 [2] 5f 08 [2] 41 15 [2] 43 14 [2] 58 12 [2] 44 15 [2] 58 3a }

  condition:
    any of them
}