rule TTP_XOR_QUAD_CurrentVersionRun_4e2c {
  strings:
    $key_4e2c = { 1d 43 [2] 39 4d [2] 12 61 [2] 3c 43 [2] 28 58 [2] 27 42 [2] 39 5f [2] 3b 5e [2] 20 58 [2] 3c 5f [2] 20 70 }

  condition:
    any of them
}