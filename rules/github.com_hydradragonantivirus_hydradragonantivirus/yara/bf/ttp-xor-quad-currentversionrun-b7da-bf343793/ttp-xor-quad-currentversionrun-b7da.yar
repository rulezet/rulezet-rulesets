rule TTP_XOR_QUAD_CurrentVersionRun_b7da {
  strings:
    $key_b7da = { e4 b5 [2] c0 bb [2] eb 97 [2] c5 b5 [2] d1 ae [2] de b4 [2] c0 a9 [2] c2 a8 [2] d9 ae [2] c5 a9 [2] d9 86 }

  condition:
    any of them
}