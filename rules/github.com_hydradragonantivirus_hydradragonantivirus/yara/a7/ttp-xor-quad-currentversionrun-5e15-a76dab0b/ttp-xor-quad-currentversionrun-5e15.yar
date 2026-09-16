rule TTP_XOR_QUAD_CurrentVersionRun_5e15 {
  strings:
    $key_5e15 = { 0d 7a [2] 29 74 [2] 02 58 [2] 2c 7a [2] 38 61 [2] 37 7b [2] 29 66 [2] 2b 67 [2] 30 61 [2] 2c 66 [2] 30 49 }

  condition:
    any of them
}