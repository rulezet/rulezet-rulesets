rule TTP_XOR_QUAD_CurrentVersionRun_1c2c {
  strings:
    $key_1c2c = { 4f 43 [2] 6b 4d [2] 40 61 [2] 6e 43 [2] 7a 58 [2] 75 42 [2] 6b 5f [2] 69 5e [2] 72 58 [2] 6e 5f [2] 72 70 }

  condition:
    any of them
}