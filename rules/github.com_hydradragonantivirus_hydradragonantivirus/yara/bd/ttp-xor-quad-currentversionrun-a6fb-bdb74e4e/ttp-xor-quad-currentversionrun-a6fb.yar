rule TTP_XOR_QUAD_CurrentVersionRun_a6fb {
  strings:
    $key_a6fb = { f5 94 [2] d1 9a [2] fa b6 [2] d4 94 [2] c0 8f [2] cf 95 [2] d1 88 [2] d3 89 [2] c8 8f [2] d4 88 [2] c8 a7 }

  condition:
    any of them
}