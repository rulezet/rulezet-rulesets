rule TTP_XOR_QUAD_CurrentVersionRun_a62d {
  strings:
    $key_a62d = { f5 42 [2] d1 4c [2] fa 60 [2] d4 42 [2] c0 59 [2] cf 43 [2] d1 5e [2] d3 5f [2] c8 59 [2] d4 5e [2] c8 71 }

  condition:
    any of them
}