rule TTP_XOR_QUAD_CurrentVersionRun_d1fb {
  strings:
    $key_d1fb = { 82 94 [2] a6 9a [2] 8d b6 [2] a3 94 [2] b7 8f [2] b8 95 [2] a6 88 [2] a4 89 [2] bf 8f [2] a3 88 [2] bf a7 }

  condition:
    any of them
}