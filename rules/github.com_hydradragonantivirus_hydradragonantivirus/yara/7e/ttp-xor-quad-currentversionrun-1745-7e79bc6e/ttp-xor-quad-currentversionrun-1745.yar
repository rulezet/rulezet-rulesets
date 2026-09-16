rule TTP_XOR_QUAD_CurrentVersionRun_1745 {
  strings:
    $key_1745 = { 44 2a [2] 60 24 [2] 4b 08 [2] 65 2a [2] 71 31 [2] 7e 2b [2] 60 36 [2] 62 37 [2] 79 31 [2] 65 36 [2] 79 19 }

  condition:
    any of them
}