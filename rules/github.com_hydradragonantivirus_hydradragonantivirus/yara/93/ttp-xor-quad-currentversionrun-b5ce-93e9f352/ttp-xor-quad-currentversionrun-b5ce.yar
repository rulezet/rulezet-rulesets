rule TTP_XOR_QUAD_CurrentVersionRun_b5ce {
  strings:
    $key_b5ce = { e6 a1 [2] c2 af [2] e9 83 [2] c7 a1 [2] d3 ba [2] dc a0 [2] c2 bd [2] c0 bc [2] db ba [2] c7 bd [2] db 92 }

  condition:
    any of them
}