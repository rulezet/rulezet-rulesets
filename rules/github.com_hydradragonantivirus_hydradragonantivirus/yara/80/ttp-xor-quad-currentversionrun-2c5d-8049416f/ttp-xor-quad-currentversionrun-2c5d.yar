rule TTP_XOR_QUAD_CurrentVersionRun_2c5d {
  strings:
    $key_2c5d = { 7f 32 [2] 5b 3c [2] 70 10 [2] 5e 32 [2] 4a 29 [2] 45 33 [2] 5b 2e [2] 59 2f [2] 42 29 [2] 5e 2e [2] 42 01 }

  condition:
    any of them
}