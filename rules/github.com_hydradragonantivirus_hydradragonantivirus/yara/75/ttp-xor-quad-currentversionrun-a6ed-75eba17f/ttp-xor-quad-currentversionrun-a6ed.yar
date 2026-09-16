rule TTP_XOR_QUAD_CurrentVersionRun_a6ed {
  strings:
    $key_a6ed = { f5 82 [2] d1 8c [2] fa a0 [2] d4 82 [2] c0 99 [2] cf 83 [2] d1 9e [2] d3 9f [2] c8 99 [2] d4 9e [2] c8 b1 }

  condition:
    any of them
}