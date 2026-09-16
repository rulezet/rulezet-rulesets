rule TTP_XOR_QUAD_CurrentVersionRun_2f5b {
  strings:
    $key_2f5b = { 7c 34 [2] 58 3a [2] 73 16 [2] 5d 34 [2] 49 2f [2] 46 35 [2] 58 28 [2] 5a 29 [2] 41 2f [2] 5d 28 [2] 41 07 }

  condition:
    any of them
}