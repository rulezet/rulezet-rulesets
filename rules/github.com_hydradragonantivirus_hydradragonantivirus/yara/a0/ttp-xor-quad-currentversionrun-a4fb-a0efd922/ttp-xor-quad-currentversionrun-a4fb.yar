rule TTP_XOR_QUAD_CurrentVersionRun_a4fb {
  strings:
    $key_a4fb = { f7 94 [2] d3 9a [2] f8 b6 [2] d6 94 [2] c2 8f [2] cd 95 [2] d3 88 [2] d1 89 [2] ca 8f [2] d6 88 [2] ca a7 }

  condition:
    any of them
}