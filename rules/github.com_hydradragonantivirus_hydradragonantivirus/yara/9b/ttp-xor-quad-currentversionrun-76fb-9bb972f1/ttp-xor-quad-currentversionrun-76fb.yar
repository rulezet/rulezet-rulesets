rule TTP_XOR_QUAD_CurrentVersionRun_76fb {
  strings:
    $key_76fb = { 25 94 [2] 01 9a [2] 2a b6 [2] 04 94 [2] 10 8f [2] 1f 95 [2] 01 88 [2] 03 89 [2] 18 8f [2] 04 88 [2] 18 a7 }

  condition:
    any of them
}