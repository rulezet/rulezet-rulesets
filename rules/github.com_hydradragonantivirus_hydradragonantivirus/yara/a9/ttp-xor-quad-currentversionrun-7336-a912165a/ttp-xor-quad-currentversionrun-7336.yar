rule TTP_XOR_QUAD_CurrentVersionRun_7336 {
  strings:
    $key_7336 = { 20 59 [2] 04 57 [2] 2f 7b [2] 01 59 [2] 15 42 [2] 1a 58 [2] 04 45 [2] 06 44 [2] 1d 42 [2] 01 45 [2] 1d 6a }

  condition:
    any of them
}