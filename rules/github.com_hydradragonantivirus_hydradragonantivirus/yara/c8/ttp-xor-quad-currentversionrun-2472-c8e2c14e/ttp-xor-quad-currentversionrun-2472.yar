rule TTP_XOR_QUAD_CurrentVersionRun_2472 {
  strings:
    $key_2472 = { 77 1d [2] 53 13 [2] 78 3f [2] 56 1d [2] 42 06 [2] 4d 1c [2] 53 01 [2] 51 00 [2] 4a 06 [2] 56 01 [2] 4a 2e }

  condition:
    any of them
}