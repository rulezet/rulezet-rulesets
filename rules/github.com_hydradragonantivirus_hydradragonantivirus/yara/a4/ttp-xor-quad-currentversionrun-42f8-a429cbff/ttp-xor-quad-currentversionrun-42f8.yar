rule TTP_XOR_QUAD_CurrentVersionRun_42f8 {
  strings:
    $key_42f8 = { 11 97 [2] 35 99 [2] 1e b5 [2] 30 97 [2] 24 8c [2] 2b 96 [2] 35 8b [2] 37 8a [2] 2c 8c [2] 30 8b [2] 2c a4 }

  condition:
    any of them
}