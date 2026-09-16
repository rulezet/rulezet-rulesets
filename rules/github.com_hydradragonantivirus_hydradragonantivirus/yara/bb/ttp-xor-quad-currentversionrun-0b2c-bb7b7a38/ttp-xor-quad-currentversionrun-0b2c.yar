rule TTP_XOR_QUAD_CurrentVersionRun_0b2c {
  strings:
    $key_0b2c = { 58 43 [2] 7c 4d [2] 57 61 [2] 79 43 [2] 6d 58 [2] 62 42 [2] 7c 5f [2] 7e 5e [2] 65 58 [2] 79 5f [2] 65 70 }

  condition:
    any of them
}