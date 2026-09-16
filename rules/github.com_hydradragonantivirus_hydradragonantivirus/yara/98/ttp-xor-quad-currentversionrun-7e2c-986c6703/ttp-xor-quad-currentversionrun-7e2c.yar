rule TTP_XOR_QUAD_CurrentVersionRun_7e2c {
  strings:
    $key_7e2c = { 2d 43 [2] 09 4d [2] 22 61 [2] 0c 43 [2] 18 58 [2] 17 42 [2] 09 5f [2] 0b 5e [2] 10 58 [2] 0c 5f [2] 10 70 }

  condition:
    any of them
}