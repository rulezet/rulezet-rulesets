rule TTP_XOR_QUAD_CurrentVersionRun_2a58 {
  strings:
    $key_2a58 = { 79 37 [2] 5d 39 [2] 76 15 [2] 58 37 [2] 4c 2c [2] 43 36 [2] 5d 2b [2] 5f 2a [2] 44 2c [2] 58 2b [2] 44 04 }

  condition:
    any of them
}