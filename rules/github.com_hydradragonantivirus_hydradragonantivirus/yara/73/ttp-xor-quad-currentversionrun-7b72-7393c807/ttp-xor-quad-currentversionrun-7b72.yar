rule TTP_XOR_QUAD_CurrentVersionRun_7b72 {
  strings:
    $key_7b72 = { 28 1d [2] 0c 13 [2] 27 3f [2] 09 1d [2] 1d 06 [2] 12 1c [2] 0c 01 [2] 0e 00 [2] 15 06 [2] 09 01 [2] 15 2e }

  condition:
    any of them
}