rule TTP_XOR_QUAD_CurrentVersionRun_1972 {
  strings:
    $key_1972 = { 4a 1d [2] 6e 13 [2] 45 3f [2] 6b 1d [2] 7f 06 [2] 70 1c [2] 6e 01 [2] 6c 00 [2] 77 06 [2] 6b 01 [2] 77 2e }

  condition:
    any of them
}