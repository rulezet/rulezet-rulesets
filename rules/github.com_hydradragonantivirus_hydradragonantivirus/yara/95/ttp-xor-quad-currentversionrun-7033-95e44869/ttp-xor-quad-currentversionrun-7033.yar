rule TTP_XOR_QUAD_CurrentVersionRun_7033 {
  strings:
    $key_7033 = { 23 5c [2] 07 52 [2] 2c 7e [2] 02 5c [2] 16 47 [2] 19 5d [2] 07 40 [2] 05 41 [2] 1e 47 [2] 02 40 [2] 1e 6f }

  condition:
    any of them
}