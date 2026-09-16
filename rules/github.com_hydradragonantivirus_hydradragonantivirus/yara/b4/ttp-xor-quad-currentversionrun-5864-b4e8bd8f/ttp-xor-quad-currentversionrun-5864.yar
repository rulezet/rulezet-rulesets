rule TTP_XOR_QUAD_CurrentVersionRun_5864 {
  strings:
    $key_5864 = { 0b 0b [2] 2f 05 [2] 04 29 [2] 2a 0b [2] 3e 10 [2] 31 0a [2] 2f 17 [2] 2d 16 [2] 36 10 [2] 2a 17 [2] 36 38 }

  condition:
    any of them
}