rule TTP_XOR_QUAD_CurrentVersionRun_e7fb {
  strings:
    $key_e7fb = { b4 94 [2] 90 9a [2] bb b6 [2] 95 94 [2] 81 8f [2] 8e 95 [2] 90 88 [2] 92 89 [2] 89 8f [2] 95 88 [2] 89 a7 }

  condition:
    any of them
}