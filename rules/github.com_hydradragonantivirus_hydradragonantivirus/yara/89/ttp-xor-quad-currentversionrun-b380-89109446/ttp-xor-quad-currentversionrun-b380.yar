rule TTP_XOR_QUAD_CurrentVersionRun_b380 {
  strings:
    $key_b380 = { e0 ef [2] c4 e1 [2] ef cd [2] c1 ef [2] d5 f4 [2] da ee [2] c4 f3 [2] c6 f2 [2] dd f4 [2] c1 f3 [2] dd dc }

  condition:
    any of them
}