rule TTP_XOR_QUAD_CurrentVersionRun_a623 {
  strings:
    $key_a623 = { f5 4c [2] d1 42 [2] fa 6e [2] d4 4c [2] c0 57 [2] cf 4d [2] d1 50 [2] d3 51 [2] c8 57 [2] d4 50 [2] c8 7f }

  condition:
    any of them
}