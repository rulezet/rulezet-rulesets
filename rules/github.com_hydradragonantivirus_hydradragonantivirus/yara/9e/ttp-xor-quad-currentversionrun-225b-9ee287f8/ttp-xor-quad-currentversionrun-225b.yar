rule TTP_XOR_QUAD_CurrentVersionRun_225b {
  strings:
    $key_225b = { 71 34 [2] 55 3a [2] 7e 16 [2] 50 34 [2] 44 2f [2] 4b 35 [2] 55 28 [2] 57 29 [2] 4c 2f [2] 50 28 [2] 4c 07 }

  condition:
    any of them
}