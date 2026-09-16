rule TTP_XOR_QUAD_CurrentVersionRun_6f2c {
  strings:
    $key_6f2c = { 3c 43 [2] 18 4d [2] 33 61 [2] 1d 43 [2] 09 58 [2] 06 42 [2] 18 5f [2] 1a 5e [2] 01 58 [2] 1d 5f [2] 01 70 }

  condition:
    any of them
}