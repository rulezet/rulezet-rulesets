rule TTP_XOR_QUAD_CurrentVersionRun_a1fb {
  strings:
    $key_a1fb = { f2 94 [2] d6 9a [2] fd b6 [2] d3 94 [2] c7 8f [2] c8 95 [2] d6 88 [2] d4 89 [2] cf 8f [2] d3 88 [2] cf a7 }

  condition:
    any of them
}