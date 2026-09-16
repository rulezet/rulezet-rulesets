rule TTP_XOR_QUAD_CurrentVersionRun_285b {
  strings:
    $key_285b = { 7b 34 [2] 5f 3a [2] 74 16 [2] 5a 34 [2] 4e 2f [2] 41 35 [2] 5f 28 [2] 5d 29 [2] 46 2f [2] 5a 28 [2] 46 07 }

  condition:
    any of them
}