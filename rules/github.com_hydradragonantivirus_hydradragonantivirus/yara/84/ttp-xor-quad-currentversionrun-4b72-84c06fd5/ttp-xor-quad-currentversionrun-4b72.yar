rule TTP_XOR_QUAD_CurrentVersionRun_4b72 {
  strings:
    $key_4b72 = { 18 1d [2] 3c 13 [2] 17 3f [2] 39 1d [2] 2d 06 [2] 22 1c [2] 3c 01 [2] 3e 00 [2] 25 06 [2] 39 01 [2] 25 2e }

  condition:
    any of them
}