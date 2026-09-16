rule TTP_XOR_QUAD_CurrentVersionRun_4b2c {
  strings:
    $key_4b2c = { 18 43 [2] 3c 4d [2] 17 61 [2] 39 43 [2] 2d 58 [2] 22 42 [2] 3c 5f [2] 3e 5e [2] 25 58 [2] 39 5f [2] 25 70 }

  condition:
    any of them
}