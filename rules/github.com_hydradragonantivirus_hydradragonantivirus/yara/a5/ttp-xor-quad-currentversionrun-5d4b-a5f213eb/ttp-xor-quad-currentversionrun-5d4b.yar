rule TTP_XOR_QUAD_CurrentVersionRun_5d4b {
  strings:
    $key_5d4b = { 0e 24 [2] 2a 2a [2] 01 06 [2] 2f 24 [2] 3b 3f [2] 34 25 [2] 2a 38 [2] 28 39 [2] 33 3f [2] 2f 38 [2] 33 17 }

  condition:
    any of them
}