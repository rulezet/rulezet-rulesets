rule TTP_XOR_QUAD_CurrentVersionRun_641b {
  strings:
    $key_641b = { 37 74 [2] 13 7a [2] 38 56 [2] 16 74 [2] 02 6f [2] 0d 75 [2] 13 68 [2] 11 69 [2] 0a 6f [2] 16 68 [2] 0a 47 }

  condition:
    any of them
}