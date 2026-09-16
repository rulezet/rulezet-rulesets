rule TTP_XOR_QUAD_CurrentVersionRun_1765 {
  strings:
    $key_1765 = { 44 0a [2] 60 04 [2] 4b 28 [2] 65 0a [2] 71 11 [2] 7e 0b [2] 60 16 [2] 62 17 [2] 79 11 [2] 65 16 [2] 79 39 }

  condition:
    any of them
}