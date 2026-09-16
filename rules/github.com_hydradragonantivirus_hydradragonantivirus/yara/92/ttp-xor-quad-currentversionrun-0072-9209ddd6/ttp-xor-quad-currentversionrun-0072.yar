rule TTP_XOR_QUAD_CurrentVersionRun_0072 {
  strings:
    $key_0072 = { 53 1d [2] 77 13 [2] 5c 3f [2] 72 1d [2] 66 06 [2] 69 1c [2] 77 01 [2] 75 00 [2] 6e 06 [2] 72 01 [2] 6e 2e }

  condition:
    any of them
}