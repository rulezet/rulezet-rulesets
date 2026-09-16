rule TTP_XOR_QUAD_CurrentVersionRun_2c34 {
  strings:
    $key_2c34 = { 7f 5b [2] 5b 55 [2] 70 79 [2] 5e 5b [2] 4a 40 [2] 45 5a [2] 5b 47 [2] 59 46 [2] 42 40 [2] 5e 47 [2] 42 68 }

  condition:
    any of them
}