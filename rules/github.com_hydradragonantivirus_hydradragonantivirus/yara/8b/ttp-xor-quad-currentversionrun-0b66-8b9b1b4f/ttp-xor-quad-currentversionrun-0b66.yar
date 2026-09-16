rule TTP_XOR_QUAD_CurrentVersionRun_0b66 {
  strings:
    $key_0b66 = { 58 09 [2] 7c 07 [2] 57 2b [2] 79 09 [2] 6d 12 [2] 62 08 [2] 7c 15 [2] 7e 14 [2] 65 12 [2] 79 15 [2] 65 3a }

  condition:
    any of them
}