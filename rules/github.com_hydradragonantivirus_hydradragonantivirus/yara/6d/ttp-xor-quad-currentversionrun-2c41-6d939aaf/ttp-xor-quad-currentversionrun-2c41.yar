rule TTP_XOR_QUAD_CurrentVersionRun_2c41 {
  strings:
    $key_2c41 = { 7f 2e [2] 5b 20 [2] 70 0c [2] 5e 2e [2] 4a 35 [2] 45 2f [2] 5b 32 [2] 59 33 [2] 42 35 [2] 5e 32 [2] 42 1d }

  condition:
    any of them
}