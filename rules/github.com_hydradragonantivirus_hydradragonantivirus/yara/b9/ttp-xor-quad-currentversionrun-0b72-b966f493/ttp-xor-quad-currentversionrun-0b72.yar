rule TTP_XOR_QUAD_CurrentVersionRun_0b72 {
  strings:
    $key_0b72 = { 58 1d [2] 7c 13 [2] 57 3f [2] 79 1d [2] 6d 06 [2] 62 1c [2] 7c 01 [2] 7e 00 [2] 65 06 [2] 79 01 [2] 65 2e }

  condition:
    any of them
}