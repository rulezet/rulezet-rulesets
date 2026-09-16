rule TTP_XOR_QUAD_CurrentVersionRun_6b72 {
  strings:
    $key_6b72 = { 38 1d [2] 1c 13 [2] 37 3f [2] 19 1d [2] 0d 06 [2] 02 1c [2] 1c 01 [2] 1e 00 [2] 05 06 [2] 19 01 [2] 05 2e }

  condition:
    any of them
}