rule TTP_XOR_QUAD_CurrentVersionRun_41fb {
  strings:
    $key_41fb = { 12 94 [2] 36 9a [2] 1d b6 [2] 33 94 [2] 27 8f [2] 28 95 [2] 36 88 [2] 34 89 [2] 2f 8f [2] 33 88 [2] 2f a7 }

  condition:
    any of them
}