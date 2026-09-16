rule TTP_XOR_QUAD_CurrentVersionRun_b703 {
  strings:
    $key_b703 = { e4 6c [2] c0 62 [2] eb 4e [2] c5 6c [2] d1 77 [2] de 6d [2] c0 70 [2] c2 71 [2] d9 77 [2] c5 70 [2] d9 5f }

  condition:
    any of them
}