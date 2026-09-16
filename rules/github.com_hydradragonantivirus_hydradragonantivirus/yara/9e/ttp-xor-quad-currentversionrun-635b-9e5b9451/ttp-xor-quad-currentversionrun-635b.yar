rule TTP_XOR_QUAD_CurrentVersionRun_635b {
  strings:
    $key_635b = { 30 34 [2] 14 3a [2] 3f 16 [2] 11 34 [2] 05 2f [2] 0a 35 [2] 14 28 [2] 16 29 [2] 0d 2f [2] 11 28 [2] 0d 07 }

  condition:
    any of them
}