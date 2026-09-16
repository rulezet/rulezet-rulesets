rule TTP_XOR_QUAD_CurrentVersionRun_7b66 {
  strings:
    $key_7b66 = { 28 09 [2] 0c 07 [2] 27 2b [2] 09 09 [2] 1d 12 [2] 12 08 [2] 0c 15 [2] 0e 14 [2] 15 12 [2] 09 15 [2] 15 3a }

  condition:
    any of them
}