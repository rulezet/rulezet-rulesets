rule TTP_XOR_QUAD_CurrentVersionRun_5d2c {
  strings:
    $key_5d2c = { 0e 43 [2] 2a 4d [2] 01 61 [2] 2f 43 [2] 3b 58 [2] 34 42 [2] 2a 5f [2] 28 5e [2] 33 58 [2] 2f 5f [2] 33 70 }

  condition:
    any of them
}