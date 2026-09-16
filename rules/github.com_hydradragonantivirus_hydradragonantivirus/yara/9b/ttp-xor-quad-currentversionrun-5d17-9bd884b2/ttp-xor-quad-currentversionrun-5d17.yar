rule TTP_XOR_QUAD_CurrentVersionRun_5d17 {
  strings:
    $key_5d17 = { 0e 78 [2] 2a 76 [2] 01 5a [2] 2f 78 [2] 3b 63 [2] 34 79 [2] 2a 64 [2] 28 65 [2] 33 63 [2] 2f 64 [2] 33 4b }

  condition:
    any of them
}