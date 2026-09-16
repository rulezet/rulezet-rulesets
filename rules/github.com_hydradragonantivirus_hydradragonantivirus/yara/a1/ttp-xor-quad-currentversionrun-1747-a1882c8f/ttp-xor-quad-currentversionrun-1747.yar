rule TTP_XOR_QUAD_CurrentVersionRun_1747 {
  strings:
    $key_1747 = { 44 28 [2] 60 26 [2] 4b 0a [2] 65 28 [2] 71 33 [2] 7e 29 [2] 60 34 [2] 62 35 [2] 79 33 [2] 65 34 [2] 79 1b }

  condition:
    any of them
}