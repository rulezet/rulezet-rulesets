rule TTP_XOR_QUAD_CurrentVersionRun_b768 {
  strings:
    $key_b768 = { e4 07 [2] c0 09 [2] eb 25 [2] c5 07 [2] d1 1c [2] de 06 [2] c0 1b [2] c2 1a [2] d9 1c [2] c5 1b [2] d9 34 }

  condition:
    any of them
}