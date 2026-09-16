rule TTP_XOR_QUAD_CurrentVersionRun_2c1c {
  strings:
    $key_2c1c = { 7f 73 [2] 5b 7d [2] 70 51 [2] 5e 73 [2] 4a 68 [2] 45 72 [2] 5b 6f [2] 59 6e [2] 42 68 [2] 5e 6f [2] 42 40 }

  condition:
    any of them
}