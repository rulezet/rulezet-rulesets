rule TTP_XOR_QUAD_CurrentVersionRun_1744 {
  strings:
    $key_1744 = { 44 2b [2] 60 25 [2] 4b 09 [2] 65 2b [2] 71 30 [2] 7e 2a [2] 60 37 [2] 62 36 [2] 79 30 [2] 65 37 [2] 79 18 }

  condition:
    any of them
}