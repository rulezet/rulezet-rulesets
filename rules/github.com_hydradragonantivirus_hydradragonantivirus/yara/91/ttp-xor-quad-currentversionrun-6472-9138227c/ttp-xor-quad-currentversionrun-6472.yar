rule TTP_XOR_QUAD_CurrentVersionRun_6472 {
  strings:
    $key_6472 = { 37 1d [2] 13 13 [2] 38 3f [2] 16 1d [2] 02 06 [2] 0d 1c [2] 13 01 [2] 11 00 [2] 0a 06 [2] 16 01 [2] 0a 2e }

  condition:
    any of them
}