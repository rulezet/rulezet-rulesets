rule TTP_XOR_QUAD_CurrentVersionRun_2c48 {
  strings:
    $key_2c48 = { 7f 27 [2] 5b 29 [2] 70 05 [2] 5e 27 [2] 4a 3c [2] 45 26 [2] 5b 3b [2] 59 3a [2] 42 3c [2] 5e 3b [2] 42 14 }

  condition:
    any of them
}