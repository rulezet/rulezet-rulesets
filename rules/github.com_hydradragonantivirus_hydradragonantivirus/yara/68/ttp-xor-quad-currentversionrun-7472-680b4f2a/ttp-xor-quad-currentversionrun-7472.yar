rule TTP_XOR_QUAD_CurrentVersionRun_7472 {
  strings:
    $key_7472 = { 27 1d [2] 03 13 [2] 28 3f [2] 06 1d [2] 12 06 [2] 1d 1c [2] 03 01 [2] 01 00 [2] 1a 06 [2] 06 01 [2] 1a 2e }

  condition:
    any of them
}