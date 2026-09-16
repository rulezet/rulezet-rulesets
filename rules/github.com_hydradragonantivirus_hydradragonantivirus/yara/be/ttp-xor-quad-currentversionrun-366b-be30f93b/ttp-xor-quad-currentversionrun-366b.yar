rule TTP_XOR_QUAD_CurrentVersionRun_366b {
  strings:
    $key_366b = { 65 04 [2] 41 0a [2] 6a 26 [2] 44 04 [2] 50 1f [2] 5f 05 [2] 41 18 [2] 43 19 [2] 58 1f [2] 44 18 [2] 58 37 }

  condition:
    any of them
}