rule TTP_XOR_QUAD_CurrentVersionRun_2c12 {
  strings:
    $key_2c12 = { 7f 7d [2] 5b 73 [2] 70 5f [2] 5e 7d [2] 4a 66 [2] 45 7c [2] 5b 61 [2] 59 60 [2] 42 66 [2] 5e 61 [2] 42 4e }

  condition:
    any of them
}