rule TTP_XOR_QUAD_CurrentVersionRun_2c1d {
  strings:
    $key_2c1d = { 7f 72 [2] 5b 7c [2] 70 50 [2] 5e 72 [2] 4a 69 [2] 45 73 [2] 5b 6e [2] 59 6f [2] 42 69 [2] 5e 6e [2] 42 41 }

  condition:
    any of them
}