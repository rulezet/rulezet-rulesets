rule TTP_XOR_QUAD_CurrentVersionRun_b6ce {
  strings:
    $key_b6ce = { e5 a1 [2] c1 af [2] ea 83 [2] c4 a1 [2] d0 ba [2] df a0 [2] c1 bd [2] c3 bc [2] d8 ba [2] c4 bd [2] d8 92 }

  condition:
    any of them
}