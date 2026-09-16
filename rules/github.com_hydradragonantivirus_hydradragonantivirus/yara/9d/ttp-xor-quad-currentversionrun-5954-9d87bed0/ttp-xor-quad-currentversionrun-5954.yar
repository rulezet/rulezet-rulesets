rule TTP_XOR_QUAD_CurrentVersionRun_5954 {
  strings:
    $key_5954 = { 0a 3b [2] 2e 35 [2] 05 19 [2] 2b 3b [2] 3f 20 [2] 30 3a [2] 2e 27 [2] 2c 26 [2] 37 20 [2] 2b 27 [2] 37 08 }

  condition:
    any of them
}