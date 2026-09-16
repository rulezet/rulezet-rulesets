rule TTP_XOR_QUAD_CurrentVersionRun_a6b4 {
  strings:
    $key_a6b4 = { f5 db [2] d1 d5 [2] fa f9 [2] d4 db [2] c0 c0 [2] cf da [2] d1 c7 [2] d3 c6 [2] c8 c0 [2] d4 c7 [2] c8 e8 }

  condition:
    any of them
}