rule TTP_XOR_QUAD_CurrentVersionRun_5f2c {
  strings:
    $key_5f2c = { 0c 43 [2] 28 4d [2] 03 61 [2] 2d 43 [2] 39 58 [2] 36 42 [2] 28 5f [2] 2a 5e [2] 31 58 [2] 2d 5f [2] 31 70 }

  condition:
    any of them
}