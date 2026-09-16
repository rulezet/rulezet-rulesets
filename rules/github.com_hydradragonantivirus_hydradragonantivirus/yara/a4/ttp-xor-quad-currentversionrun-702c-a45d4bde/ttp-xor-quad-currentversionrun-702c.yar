rule TTP_XOR_QUAD_CurrentVersionRun_702c {
  strings:
    $key_702c = { 23 43 [2] 07 4d [2] 2c 61 [2] 02 43 [2] 16 58 [2] 19 42 [2] 07 5f [2] 05 5e [2] 1e 58 [2] 02 5f [2] 1e 70 }

  condition:
    any of them
}