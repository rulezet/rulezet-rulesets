rule TTP_XOR_QUAD_CurrentVersionRun_5264 {
  strings:
    $key_5264 = { 01 0b [2] 25 05 [2] 0e 29 [2] 20 0b [2] 34 10 [2] 3b 0a [2] 25 17 [2] 27 16 [2] 3c 10 [2] 20 17 [2] 3c 38 }

  condition:
    any of them
}