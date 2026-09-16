rule TTP_XOR_QUAD_CurrentVersionRun_77fb {
  strings:
    $key_77fb = { 24 94 [2] 00 9a [2] 2b b6 [2] 05 94 [2] 11 8f [2] 1e 95 [2] 00 88 [2] 02 89 [2] 19 8f [2] 05 88 [2] 19 a7 }

  condition:
    any of them
}