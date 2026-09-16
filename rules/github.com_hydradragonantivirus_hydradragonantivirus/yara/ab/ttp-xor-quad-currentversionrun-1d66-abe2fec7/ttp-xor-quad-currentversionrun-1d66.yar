rule TTP_XOR_QUAD_CurrentVersionRun_1d66 {
  strings:
    $key_1d66 = { 4e 09 [2] 6a 07 [2] 41 2b [2] 6f 09 [2] 7b 12 [2] 74 08 [2] 6a 15 [2] 68 14 [2] 73 12 [2] 6f 15 [2] 73 3a }

  condition:
    any of them
}