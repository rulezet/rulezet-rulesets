rule TTP_XOR_QUAD_CurrentVersionRun_2c59 {
  strings:
    $key_2c59 = { 7f 36 [2] 5b 38 [2] 70 14 [2] 5e 36 [2] 4a 2d [2] 45 37 [2] 5b 2a [2] 59 2b [2] 42 2d [2] 5e 2a [2] 42 05 }

  condition:
    any of them
}