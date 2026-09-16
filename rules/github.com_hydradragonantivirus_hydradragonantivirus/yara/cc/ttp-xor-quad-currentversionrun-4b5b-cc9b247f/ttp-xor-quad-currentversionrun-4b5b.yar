rule TTP_XOR_QUAD_CurrentVersionRun_4b5b {
  strings:
    $key_4b5b = { 18 34 [2] 3c 3a [2] 17 16 [2] 39 34 [2] 2d 2f [2] 22 35 [2] 3c 28 [2] 3e 29 [2] 25 2f [2] 39 28 [2] 25 07 }

  condition:
    any of them
}