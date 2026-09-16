rule TTP_XOR_QUAD_CurrentVersionRun_2c7a {
  strings:
    $key_2c7a = { 7f 15 [2] 5b 1b [2] 70 37 [2] 5e 15 [2] 4a 0e [2] 45 14 [2] 5b 09 [2] 59 08 [2] 42 0e [2] 5e 09 [2] 42 26 }

  condition:
    any of them
}