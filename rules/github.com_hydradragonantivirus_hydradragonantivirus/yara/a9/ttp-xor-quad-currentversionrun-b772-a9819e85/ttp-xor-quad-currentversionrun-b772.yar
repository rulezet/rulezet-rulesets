rule TTP_XOR_QUAD_CurrentVersionRun_b772 {
  strings:
    $key_b772 = { e4 1d [2] c0 13 [2] eb 3f [2] c5 1d [2] d1 06 [2] de 1c [2] c0 01 [2] c2 00 [2] d9 06 [2] c5 01 [2] d9 2e }

  condition:
    any of them
}