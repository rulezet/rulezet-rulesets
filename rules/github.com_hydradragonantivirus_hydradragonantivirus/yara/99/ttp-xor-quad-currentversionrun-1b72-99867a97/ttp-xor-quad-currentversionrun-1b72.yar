rule TTP_XOR_QUAD_CurrentVersionRun_1b72 {
  strings:
    $key_1b72 = { 48 1d [2] 6c 13 [2] 47 3f [2] 69 1d [2] 7d 06 [2] 72 1c [2] 6c 01 [2] 6e 00 [2] 75 06 [2] 69 01 [2] 75 2e }

  condition:
    any of them
}