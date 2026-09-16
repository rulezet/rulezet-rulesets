rule TTP_XOR_QUAD_CurrentVersionRun_5955 {
  strings:
    $key_5955 = { 0a 3a [2] 2e 34 [2] 05 18 [2] 2b 3a [2] 3f 21 [2] 30 3b [2] 2e 26 [2] 2c 27 [2] 37 21 [2] 2b 26 [2] 37 09 }

  condition:
    any of them
}