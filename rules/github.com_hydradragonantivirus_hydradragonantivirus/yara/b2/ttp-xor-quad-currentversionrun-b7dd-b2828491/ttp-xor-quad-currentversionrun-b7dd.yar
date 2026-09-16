rule TTP_XOR_QUAD_CurrentVersionRun_b7dd {
  strings:
    $key_b7dd = { e4 b2 [2] c0 bc [2] eb 90 [2] c5 b2 [2] d1 a9 [2] de b3 [2] c0 ae [2] c2 af [2] d9 a9 [2] c5 ae [2] d9 81 }

  condition:
    any of them
}