rule TTP_XOR_QUAD_CurrentVersionRun_6d2c {
  strings:
    $key_6d2c = { 3e 43 [2] 1a 4d [2] 31 61 [2] 1f 43 [2] 0b 58 [2] 04 42 [2] 1a 5f [2] 18 5e [2] 03 58 [2] 1f 5f [2] 03 70 }

  condition:
    any of them
}