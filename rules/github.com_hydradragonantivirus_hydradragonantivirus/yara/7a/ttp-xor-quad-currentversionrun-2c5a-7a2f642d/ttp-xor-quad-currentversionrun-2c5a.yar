rule TTP_XOR_QUAD_CurrentVersionRun_2c5a {
  strings:
    $key_2c5a = { 7f 35 [2] 5b 3b [2] 70 17 [2] 5e 35 [2] 4a 2e [2] 45 34 [2] 5b 29 [2] 59 28 [2] 42 2e [2] 5e 29 [2] 42 06 }

  condition:
    any of them
}