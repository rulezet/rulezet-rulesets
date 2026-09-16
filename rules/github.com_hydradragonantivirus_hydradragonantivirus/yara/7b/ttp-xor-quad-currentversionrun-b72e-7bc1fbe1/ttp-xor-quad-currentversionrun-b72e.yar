rule TTP_XOR_QUAD_CurrentVersionRun_b72e {
  strings:
    $key_b72e = { e4 41 [2] c0 4f [2] eb 63 [2] c5 41 [2] d1 5a [2] de 40 [2] c0 5d [2] c2 5c [2] d9 5a [2] c5 5d [2] d9 72 }

  condition:
    any of them
}