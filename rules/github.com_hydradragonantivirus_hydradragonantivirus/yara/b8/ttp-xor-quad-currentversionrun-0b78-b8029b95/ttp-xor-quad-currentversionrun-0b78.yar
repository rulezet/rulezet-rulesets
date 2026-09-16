rule TTP_XOR_QUAD_CurrentVersionRun_0b78 {
  strings:
    $key_0b78 = { 58 17 [2] 7c 19 [2] 57 35 [2] 79 17 [2] 6d 0c [2] 62 16 [2] 7c 0b [2] 7e 0a [2] 65 0c [2] 79 0b [2] 65 24 }

  condition:
    any of them
}