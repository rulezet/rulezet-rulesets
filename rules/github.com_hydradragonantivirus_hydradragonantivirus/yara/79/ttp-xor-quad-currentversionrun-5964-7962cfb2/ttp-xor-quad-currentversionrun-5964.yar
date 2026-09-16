rule TTP_XOR_QUAD_CurrentVersionRun_5964 {
  strings:
    $key_5964 = { 0a 0b [2] 2e 05 [2] 05 29 [2] 2b 0b [2] 3f 10 [2] 30 0a [2] 2e 17 [2] 2c 16 [2] 37 10 [2] 2b 17 [2] 37 38 }

  condition:
    any of them
}