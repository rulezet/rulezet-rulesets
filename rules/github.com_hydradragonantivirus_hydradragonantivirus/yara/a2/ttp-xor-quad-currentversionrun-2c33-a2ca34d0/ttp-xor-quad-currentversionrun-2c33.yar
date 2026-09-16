rule TTP_XOR_QUAD_CurrentVersionRun_2c33 {
  strings:
    $key_2c33 = { 7f 5c [2] 5b 52 [2] 70 7e [2] 5e 5c [2] 4a 47 [2] 45 5d [2] 5b 40 [2] 59 41 [2] 42 47 [2] 5e 40 [2] 42 6f }

  condition:
    any of them
}