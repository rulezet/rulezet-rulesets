rule TTP_XOR_QUAD_CurrentVersionRun_2c1a {
  strings:
    $key_2c1a = { 7f 75 [2] 5b 7b [2] 70 57 [2] 5e 75 [2] 4a 6e [2] 45 74 [2] 5b 69 [2] 59 68 [2] 42 6e [2] 5e 69 [2] 42 46 }

  condition:
    any of them
}