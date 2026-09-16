rule TTP_XOR_QUAD_CurrentVersionRun_f4fb {
  strings:
    $key_f4fb = { a7 94 [2] 83 9a [2] a8 b6 [2] 86 94 [2] 92 8f [2] 9d 95 [2] 83 88 [2] 81 89 [2] 9a 8f [2] 86 88 [2] 9a a7 }

  condition:
    any of them
}