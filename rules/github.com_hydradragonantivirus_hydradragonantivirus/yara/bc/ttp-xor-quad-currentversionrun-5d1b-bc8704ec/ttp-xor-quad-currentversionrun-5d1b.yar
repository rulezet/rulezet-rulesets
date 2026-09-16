rule TTP_XOR_QUAD_CurrentVersionRun_5d1b {
  strings:
    $key_5d1b = { 0e 74 [2] 2a 7a [2] 01 56 [2] 2f 74 [2] 3b 6f [2] 34 75 [2] 2a 68 [2] 28 69 [2] 33 6f [2] 2f 68 [2] 33 47 }

  condition:
    any of them
}