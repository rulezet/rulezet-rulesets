rule TTP_XOR_QUAD_CurrentVersionRun_26fb {
  strings:
    $key_26fb = { 75 94 [2] 51 9a [2] 7a b6 [2] 54 94 [2] 40 8f [2] 4f 95 [2] 51 88 [2] 53 89 [2] 48 8f [2] 54 88 [2] 48 a7 }

  condition:
    any of them
}