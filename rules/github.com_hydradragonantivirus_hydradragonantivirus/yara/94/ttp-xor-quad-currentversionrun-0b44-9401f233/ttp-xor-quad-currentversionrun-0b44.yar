rule TTP_XOR_QUAD_CurrentVersionRun_0b44 {
  strings:
    $key_0b44 = { 58 2b [2] 7c 25 [2] 57 09 [2] 79 2b [2] 6d 30 [2] 62 2a [2] 7c 37 [2] 7e 36 [2] 65 30 [2] 79 37 [2] 65 18 }

  condition:
    any of them
}