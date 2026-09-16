rule TTP_XOR_QUAD_CurrentVersionRun_b0fb {
  strings:
    $key_b0fb = { e3 94 [2] c7 9a [2] ec b6 [2] c2 94 [2] d6 8f [2] d9 95 [2] c7 88 [2] c5 89 [2] de 8f [2] c2 88 [2] de a7 }

  condition:
    any of them
}