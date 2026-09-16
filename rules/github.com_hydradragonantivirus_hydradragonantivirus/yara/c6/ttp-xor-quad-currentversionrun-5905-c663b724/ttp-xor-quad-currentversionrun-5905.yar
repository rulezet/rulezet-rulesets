rule TTP_XOR_QUAD_CurrentVersionRun_5905 {
  strings:
    $key_5905 = { 0a 6a [2] 2e 64 [2] 05 48 [2] 2b 6a [2] 3f 71 [2] 30 6b [2] 2e 76 [2] 2c 77 [2] 37 71 [2] 2b 76 [2] 37 59 }

  condition:
    any of them
}