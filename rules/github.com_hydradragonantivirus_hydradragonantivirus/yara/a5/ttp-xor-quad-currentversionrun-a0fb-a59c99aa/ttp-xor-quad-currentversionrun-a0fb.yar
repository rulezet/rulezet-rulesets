rule TTP_XOR_QUAD_CurrentVersionRun_a0fb {
  strings:
    $key_a0fb = { f3 94 [2] d7 9a [2] fc b6 [2] d2 94 [2] c6 8f [2] c9 95 [2] d7 88 [2] d5 89 [2] ce 8f [2] d2 88 [2] ce a7 }

  condition:
    any of them
}