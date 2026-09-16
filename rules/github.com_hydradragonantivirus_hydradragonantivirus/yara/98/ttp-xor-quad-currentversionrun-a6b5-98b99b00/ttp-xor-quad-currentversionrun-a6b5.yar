rule TTP_XOR_QUAD_CurrentVersionRun_a6b5 {
  strings:
    $key_a6b5 = { f5 da [2] d1 d4 [2] fa f8 [2] d4 da [2] c0 c1 [2] cf db [2] d1 c6 [2] d3 c7 [2] c8 c1 [2] d4 c6 [2] c8 e9 }

  condition:
    any of them
}