rule TTP_XOR_QUAD_CurrentVersionRun_67fb {
  strings:
    $key_67fb = { 34 94 [2] 10 9a [2] 3b b6 [2] 15 94 [2] 01 8f [2] 0e 95 [2] 10 88 [2] 12 89 [2] 09 8f [2] 15 88 [2] 09 a7 }

  condition:
    any of them
}