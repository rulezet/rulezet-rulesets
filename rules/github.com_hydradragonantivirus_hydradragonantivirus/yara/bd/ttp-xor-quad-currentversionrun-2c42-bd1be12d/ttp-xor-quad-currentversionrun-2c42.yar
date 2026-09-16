rule TTP_XOR_QUAD_CurrentVersionRun_2c42 {
  strings:
    $key_2c42 = { 7f 2d [2] 5b 23 [2] 70 0f [2] 5e 2d [2] 4a 36 [2] 45 2c [2] 5b 31 [2] 59 30 [2] 42 36 [2] 5e 31 [2] 42 1e }

  condition:
    any of them
}