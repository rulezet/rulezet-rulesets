rule TTP_XOR_QUAD_CurrentVersionRun_b7ce {
  strings:
    $key_b7ce = { e4 a1 [2] c0 af [2] eb 83 [2] c5 a1 [2] d1 ba [2] de a0 [2] c0 bd [2] c2 bc [2] d9 ba [2] c5 bd [2] d9 92 }

  condition:
    any of them
}