rule TTP_XOR_QUAD_CurrentVersionRun_5d6b {
  strings:
    $key_5d6b = { 0e 04 [2] 2a 0a [2] 01 26 [2] 2f 04 [2] 3b 1f [2] 34 05 [2] 2a 18 [2] 28 19 [2] 33 1f [2] 2f 18 [2] 33 37 }

  condition:
    any of them
}