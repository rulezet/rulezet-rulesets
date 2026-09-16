rule TTP_XOR_QUAD_CurrentVersionRun_2c58 {
  strings:
    $key_2c58 = { 7f 37 [2] 5b 39 [2] 70 15 [2] 5e 37 [2] 4a 2c [2] 45 36 [2] 5b 2b [2] 59 2a [2] 42 2c [2] 5e 2b [2] 42 04 }

  condition:
    any of them
}