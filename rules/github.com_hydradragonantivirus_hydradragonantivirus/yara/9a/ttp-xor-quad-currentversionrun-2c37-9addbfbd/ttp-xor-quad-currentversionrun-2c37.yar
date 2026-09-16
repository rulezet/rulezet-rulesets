rule TTP_XOR_QUAD_CurrentVersionRun_2c37 {
  strings:
    $key_2c37 = { 7f 58 [2] 5b 56 [2] 70 7a [2] 5e 58 [2] 4a 43 [2] 45 59 [2] 5b 44 [2] 59 45 [2] 42 43 [2] 5e 44 [2] 42 6b }

  condition:
    any of them
}