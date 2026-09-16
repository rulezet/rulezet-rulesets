rule TTP_XOR_QUAD_CurrentVersionRun_a65a {
  strings:
    $key_a65a = { f5 35 [2] d1 3b [2] fa 17 [2] d4 35 [2] c0 2e [2] cf 34 [2] d1 29 [2] d3 28 [2] c8 2e [2] d4 29 [2] c8 06 }

  condition:
    any of them
}