rule TTP_XOR_QUAD_CurrentVersionRun_a5fb {
  strings:
    $key_a5fb = { f6 94 [2] d2 9a [2] f9 b6 [2] d7 94 [2] c3 8f [2] cc 95 [2] d2 88 [2] d0 89 [2] cb 8f [2] d7 88 [2] cb a7 }

  condition:
    any of them
}