rule TTP_XOR_QUAD_CurrentVersionRun_5839 {
  strings:
    $key_5839 = { 0b 56 [2] 2f 58 [2] 04 74 [2] 2a 56 [2] 3e 4d [2] 31 57 [2] 2f 4a [2] 2d 4b [2] 36 4d [2] 2a 4a [2] 36 65 }

  condition:
    any of them
}