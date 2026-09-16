rule TTP_XOR_QUAD_CurrentVersionRun_6f72 {
  strings:
    $key_6f72 = { 3c 1d [2] 18 13 [2] 33 3f [2] 1d 1d [2] 09 06 [2] 06 1c [2] 18 01 [2] 1a 00 [2] 01 06 [2] 1d 01 [2] 01 2e }

  condition:
    any of them
}