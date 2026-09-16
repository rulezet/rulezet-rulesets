rule TTP_XOR_QUAD_CurrentVersionRun_b480 {
  strings:
    $key_b480 = { e7 ef [2] c3 e1 [2] e8 cd [2] c6 ef [2] d2 f4 [2] dd ee [2] c3 f3 [2] c1 f2 [2] da f4 [2] c6 f3 [2] da dc }

  condition:
    any of them
}