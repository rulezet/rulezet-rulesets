rule TTP_XOR_QUAD_CurrentVersionRun_3677 {
  strings:
    $key_3677 = { 65 18 [2] 41 16 [2] 6a 3a [2] 44 18 [2] 50 03 [2] 5f 19 [2] 41 04 [2] 43 05 [2] 58 03 [2] 44 04 [2] 58 2b }

  condition:
    any of them
}