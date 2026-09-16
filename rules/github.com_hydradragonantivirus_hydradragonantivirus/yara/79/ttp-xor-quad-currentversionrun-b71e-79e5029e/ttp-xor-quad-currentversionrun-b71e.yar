rule TTP_XOR_QUAD_CurrentVersionRun_b71e {
  strings:
    $key_b71e = { e4 71 [2] c0 7f [2] eb 53 [2] c5 71 [2] d1 6a [2] de 70 [2] c0 6d [2] c2 6c [2] d9 6a [2] c5 6d [2] d9 42 }

  condition:
    any of them
}