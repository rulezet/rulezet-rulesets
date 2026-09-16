rule TTP_XOR_QUAD_CurrentVersionRun_175b {
  strings:
    $key_175b = { 44 34 [2] 60 3a [2] 4b 16 [2] 65 34 [2] 71 2f [2] 7e 35 [2] 60 28 [2] 62 29 [2] 79 2f [2] 65 28 [2] 79 07 }

  condition:
    any of them
}