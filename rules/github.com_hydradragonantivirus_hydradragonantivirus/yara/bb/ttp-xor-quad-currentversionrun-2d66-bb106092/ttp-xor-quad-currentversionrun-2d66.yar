rule TTP_XOR_QUAD_CurrentVersionRun_2d66 {
  strings:
    $key_2d66 = { 7e 09 [2] 5a 07 [2] 71 2b [2] 5f 09 [2] 4b 12 [2] 44 08 [2] 5a 15 [2] 58 14 [2] 43 12 [2] 5f 15 [2] 43 3a }

  condition:
    any of them
}