rule TTP_XOR_QUAD_CurrentVersionRun_5824 {
  strings:
    $key_5824 = { 0b 4b [2] 2f 45 [2] 04 69 [2] 2a 4b [2] 3e 50 [2] 31 4a [2] 2f 57 [2] 2d 56 [2] 36 50 [2] 2a 57 [2] 36 78 }

  condition:
    any of them
}