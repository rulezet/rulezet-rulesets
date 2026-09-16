rule TTP_XOR_QUAD_CurrentVersionRun_1e72 {
  strings:
    $key_1e72 = { 4d 1d [2] 69 13 [2] 42 3f [2] 6c 1d [2] 78 06 [2] 77 1c [2] 69 01 [2] 6b 00 [2] 70 06 [2] 6c 01 [2] 70 2e }

  condition:
    any of them
}