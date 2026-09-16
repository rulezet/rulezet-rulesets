rule TTP_XOR_QUAD_CurrentVersionRun_a6fa {
  strings:
    $key_a6fa = { f5 95 [2] d1 9b [2] fa b7 [2] d4 95 [2] c0 8e [2] cf 94 [2] d1 89 [2] d3 88 [2] c8 8e [2] d4 89 [2] c8 a6 }

  condition:
    any of them
}