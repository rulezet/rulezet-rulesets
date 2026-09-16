rule TTP_XOR_QUAD_CurrentVersionRun_f3fb {
  strings:
    $key_f3fb = { a0 94 [2] 84 9a [2] af b6 [2] 81 94 [2] 95 8f [2] 9a 95 [2] 84 88 [2] 86 89 [2] 9d 8f [2] 81 88 [2] 9d a7 }

  condition:
    any of them
}