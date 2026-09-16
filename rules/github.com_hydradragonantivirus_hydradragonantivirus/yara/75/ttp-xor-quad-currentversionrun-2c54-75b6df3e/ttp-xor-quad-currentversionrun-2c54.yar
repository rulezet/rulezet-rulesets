rule TTP_XOR_QUAD_CurrentVersionRun_2c54 {
  strings:
    $key_2c54 = { 7f 3b [2] 5b 35 [2] 70 19 [2] 5e 3b [2] 4a 20 [2] 45 3a [2] 5b 27 [2] 59 26 [2] 42 20 [2] 5e 27 [2] 42 08 }

  condition:
    any of them
}