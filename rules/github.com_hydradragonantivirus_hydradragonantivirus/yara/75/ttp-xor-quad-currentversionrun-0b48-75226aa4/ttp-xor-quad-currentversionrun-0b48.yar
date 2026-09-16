rule TTP_XOR_QUAD_CurrentVersionRun_0b48 {
  strings:
    $key_0b48 = { 58 27 [2] 7c 29 [2] 57 05 [2] 79 27 [2] 6d 3c [2] 62 26 [2] 7c 3b [2] 7e 3a [2] 65 3c [2] 79 3b [2] 65 14 }

  condition:
    any of them
}