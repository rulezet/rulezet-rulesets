rule TTP_XOR_QUAD_CurrentVersionRun_07fb {
  strings:
    $key_07fb = { 54 94 [2] 70 9a [2] 5b b6 [2] 75 94 [2] 61 8f [2] 6e 95 [2] 70 88 [2] 72 89 [2] 69 8f [2] 75 88 [2] 69 a7 }

  condition:
    any of them
}