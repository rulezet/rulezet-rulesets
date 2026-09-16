rule TTP_XOR_QUAD_CurrentVersionRun_43fb {
  strings:
    $key_43fb = { 10 94 [2] 34 9a [2] 1f b6 [2] 31 94 [2] 25 8f [2] 2a 95 [2] 34 88 [2] 36 89 [2] 2d 8f [2] 31 88 [2] 2d a7 }

  condition:
    any of them
}