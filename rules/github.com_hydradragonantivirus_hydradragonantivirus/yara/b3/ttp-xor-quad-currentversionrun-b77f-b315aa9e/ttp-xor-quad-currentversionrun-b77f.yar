rule TTP_XOR_QUAD_CurrentVersionRun_b77f {
  strings:
    $key_b77f = { e4 10 [2] c0 1e [2] eb 32 [2] c5 10 [2] d1 0b [2] de 11 [2] c0 0c [2] c2 0d [2] d9 0b [2] c5 0c [2] d9 23 }

  condition:
    any of them
}