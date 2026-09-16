rule TTP_XOR_QUAD_CurrentVersionRun_2c61 {
  strings:
    $key_2c61 = { 7f 0e [2] 5b 00 [2] 70 2c [2] 5e 0e [2] 4a 15 [2] 45 0f [2] 5b 12 [2] 59 13 [2] 42 15 [2] 5e 12 [2] 42 3d }

  condition:
    any of them
}