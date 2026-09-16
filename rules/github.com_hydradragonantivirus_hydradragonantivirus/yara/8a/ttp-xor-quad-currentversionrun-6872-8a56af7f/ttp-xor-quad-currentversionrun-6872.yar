rule TTP_XOR_QUAD_CurrentVersionRun_6872 {
  strings:
    $key_6872 = { 3b 1d [2] 1f 13 [2] 34 3f [2] 1a 1d [2] 0e 06 [2] 01 1c [2] 1f 01 [2] 1d 00 [2] 06 06 [2] 1a 01 [2] 06 2e }

  condition:
    any of them
}