rule TTP_XOR_QUAD_CurrentVersionRun_a6d2 {
  strings:
    $key_a6d2 = { f5 bd [2] d1 b3 [2] fa 9f [2] d4 bd [2] c0 a6 [2] cf bc [2] d1 a1 [2] d3 a0 [2] c8 a6 [2] d4 a1 [2] c8 8e }

  condition:
    any of them
}