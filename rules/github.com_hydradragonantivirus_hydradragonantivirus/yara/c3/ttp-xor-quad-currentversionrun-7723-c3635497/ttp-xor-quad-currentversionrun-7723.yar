rule TTP_XOR_QUAD_CurrentVersionRun_7723 {
  strings:
    $key_7723 = { 24 4c [2] 00 42 [2] 2b 6e [2] 05 4c [2] 11 57 [2] 1e 4d [2] 00 50 [2] 02 51 [2] 19 57 [2] 05 50 [2] 19 7f }

  condition:
    any of them
}