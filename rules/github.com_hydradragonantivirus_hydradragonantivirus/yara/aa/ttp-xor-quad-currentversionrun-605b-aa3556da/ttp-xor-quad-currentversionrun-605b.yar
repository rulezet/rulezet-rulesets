rule TTP_XOR_QUAD_CurrentVersionRun_605b {
  strings:
    $key_605b = { 33 34 [2] 17 3a [2] 3c 16 [2] 12 34 [2] 06 2f [2] 09 35 [2] 17 28 [2] 15 29 [2] 0e 2f [2] 12 28 [2] 0e 07 }

  condition:
    any of them
}