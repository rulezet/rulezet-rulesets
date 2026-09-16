rule TTP_XOR_QUAD_CurrentVersionRun_2c55 {
  strings:
    $key_2c55 = { 7f 3a [2] 5b 34 [2] 70 18 [2] 5e 3a [2] 4a 21 [2] 45 3b [2] 5b 26 [2] 59 27 [2] 42 21 [2] 5e 26 [2] 42 09 }

  condition:
    any of them
}