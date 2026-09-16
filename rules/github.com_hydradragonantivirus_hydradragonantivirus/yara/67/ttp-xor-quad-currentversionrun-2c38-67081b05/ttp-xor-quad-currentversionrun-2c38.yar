rule TTP_XOR_QUAD_CurrentVersionRun_2c38 {
  strings:
    $key_2c38 = { 7f 57 [2] 5b 59 [2] 70 75 [2] 5e 57 [2] 4a 4c [2] 45 56 [2] 5b 4b [2] 59 4a [2] 42 4c [2] 5e 4b [2] 42 64 }

  condition:
    any of them
}