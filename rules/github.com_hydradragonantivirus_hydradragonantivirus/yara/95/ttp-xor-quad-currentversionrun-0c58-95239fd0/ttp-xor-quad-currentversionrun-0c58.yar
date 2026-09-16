rule TTP_XOR_QUAD_CurrentVersionRun_0c58 {
  strings:
    $key_0c58 = { 5f 37 [2] 7b 39 [2] 50 15 [2] 7e 37 [2] 6a 2c [2] 65 36 [2] 7b 2b [2] 79 2a [2] 62 2c [2] 7e 2b [2] 62 04 }

  condition:
    any of them
}