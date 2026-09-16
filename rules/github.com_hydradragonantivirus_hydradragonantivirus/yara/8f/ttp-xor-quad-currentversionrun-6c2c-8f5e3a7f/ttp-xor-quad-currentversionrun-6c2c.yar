rule TTP_XOR_QUAD_CurrentVersionRun_6c2c {
  strings:
    $key_6c2c = { 3f 43 [2] 1b 4d [2] 30 61 [2] 1e 43 [2] 0a 58 [2] 05 42 [2] 1b 5f [2] 19 5e [2] 02 58 [2] 1e 5f [2] 02 70 }

  condition:
    any of them
}