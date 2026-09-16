rule TTP_XOR_QUAD_CurrentVersionRun_1b2c {
  strings:
    $key_1b2c = { 48 43 [2] 6c 4d [2] 47 61 [2] 69 43 [2] 7d 58 [2] 72 42 [2] 6c 5f [2] 6e 5e [2] 75 58 [2] 69 5f [2] 75 70 }

  condition:
    any of them
}