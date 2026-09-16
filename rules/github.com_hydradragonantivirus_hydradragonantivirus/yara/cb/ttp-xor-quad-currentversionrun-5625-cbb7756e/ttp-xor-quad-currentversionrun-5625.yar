rule TTP_XOR_QUAD_CurrentVersionRun_5625 {
  strings:
    $key_5625 = { 05 4a [2] 21 44 [2] 0a 68 [2] 24 4a [2] 30 51 [2] 3f 4b [2] 21 56 [2] 23 57 [2] 38 51 [2] 24 56 [2] 38 79 }

  condition:
    any of them
}