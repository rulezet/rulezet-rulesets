rule TTP_XOR_QUAD_CurrentVersionRun_6b2c {
  strings:
    $key_6b2c = { 38 43 [2] 1c 4d [2] 37 61 [2] 19 43 [2] 0d 58 [2] 02 42 [2] 1c 5f [2] 1e 5e [2] 05 58 [2] 19 5f [2] 05 70 }

  condition:
    any of them
}