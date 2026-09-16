rule TTP_XOR_QUAD_CurrentVersionRun_0b45 {
  strings:
    $key_0b45 = { 58 2a [2] 7c 24 [2] 57 08 [2] 79 2a [2] 6d 31 [2] 62 2b [2] 7c 36 [2] 7e 37 [2] 65 31 [2] 79 36 [2] 65 19 }

  condition:
    any of them
}