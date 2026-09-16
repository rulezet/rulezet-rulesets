rule TTP_XOR_QUAD_CurrentVersionRun_5940 {
  strings:
    $key_5940 = { 0a 2f [2] 2e 21 [2] 05 0d [2] 2b 2f [2] 3f 34 [2] 30 2e [2] 2e 33 [2] 2c 32 [2] 37 34 [2] 2b 33 [2] 37 1c }

  condition:
    any of them
}