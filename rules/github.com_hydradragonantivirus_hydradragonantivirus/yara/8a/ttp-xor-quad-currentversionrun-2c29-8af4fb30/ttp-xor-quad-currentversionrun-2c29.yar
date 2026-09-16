rule TTP_XOR_QUAD_CurrentVersionRun_2c29 {
  strings:
    $key_2c29 = { 7f 46 [2] 5b 48 [2] 70 64 [2] 5e 46 [2] 4a 5d [2] 45 47 [2] 5b 5a [2] 59 5b [2] 42 5d [2] 5e 5a [2] 42 75 }

  condition:
    any of them
}