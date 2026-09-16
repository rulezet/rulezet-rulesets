rule TTP_XOR_QUAD_CurrentVersionRun_a62c {
  strings:
    $key_a62c = { f5 43 [2] d1 4d [2] fa 61 [2] d4 43 [2] c0 58 [2] cf 42 [2] d1 5f [2] d3 5e [2] c8 58 [2] d4 5f [2] c8 70 }

  condition:
    any of them
}