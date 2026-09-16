rule TTP_XOR_QUAD_CurrentVersionRun_b713 {
  strings:
    $key_b713 = { e4 7c [2] c0 72 [2] eb 5e [2] c5 7c [2] d1 67 [2] de 7d [2] c0 60 [2] c2 61 [2] d9 67 [2] c5 60 [2] d9 4f }

  condition:
    any of them
}