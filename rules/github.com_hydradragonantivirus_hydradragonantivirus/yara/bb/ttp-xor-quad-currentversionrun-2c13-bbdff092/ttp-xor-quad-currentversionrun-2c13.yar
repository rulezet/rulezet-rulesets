rule TTP_XOR_QUAD_CurrentVersionRun_2c13 {
  strings:
    $key_2c13 = { 7f 7c [2] 5b 72 [2] 70 5e [2] 5e 7c [2] 4a 67 [2] 45 7d [2] 5b 60 [2] 59 61 [2] 42 67 [2] 5e 60 [2] 42 4f }

  condition:
    any of them
}