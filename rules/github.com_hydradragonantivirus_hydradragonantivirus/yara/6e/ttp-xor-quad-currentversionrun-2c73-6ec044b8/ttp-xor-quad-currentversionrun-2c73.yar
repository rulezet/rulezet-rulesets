rule TTP_XOR_QUAD_CurrentVersionRun_2c73 {
  strings:
    $key_2c73 = { 7f 1c [2] 5b 12 [2] 70 3e [2] 5e 1c [2] 4a 07 [2] 45 1d [2] 5b 00 [2] 59 01 [2] 42 07 [2] 5e 00 [2] 42 2f }

  condition:
    any of them
}