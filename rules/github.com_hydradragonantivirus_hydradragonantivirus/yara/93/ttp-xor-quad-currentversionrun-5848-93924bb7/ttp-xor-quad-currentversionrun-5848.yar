rule TTP_XOR_QUAD_CurrentVersionRun_5848 {
  strings:
    $key_5848 = { 0b 27 [2] 2f 29 [2] 04 05 [2] 2a 27 [2] 3e 3c [2] 31 26 [2] 2f 3b [2] 2d 3a [2] 36 3c [2] 2a 3b [2] 36 14 }

  condition:
    any of them
}