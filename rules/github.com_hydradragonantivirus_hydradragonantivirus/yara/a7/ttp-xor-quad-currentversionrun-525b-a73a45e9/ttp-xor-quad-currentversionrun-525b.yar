rule TTP_XOR_QUAD_CurrentVersionRun_525b {
  strings:
    $key_525b = { 01 34 [2] 25 3a [2] 0e 16 [2] 20 34 [2] 34 2f [2] 3b 35 [2] 25 28 [2] 27 29 [2] 3c 2f [2] 20 28 [2] 3c 07 }

  condition:
    any of them
}