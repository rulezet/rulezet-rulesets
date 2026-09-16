rule TTP_XOR_QUAD_CurrentVersionRun_b680 {
  strings:
    $key_b680 = { e5 ef [2] c1 e1 [2] ea cd [2] c4 ef [2] d0 f4 [2] df ee [2] c1 f3 [2] c3 f2 [2] d8 f4 [2] c4 f3 [2] d8 dc }

  condition:
    any of them
}