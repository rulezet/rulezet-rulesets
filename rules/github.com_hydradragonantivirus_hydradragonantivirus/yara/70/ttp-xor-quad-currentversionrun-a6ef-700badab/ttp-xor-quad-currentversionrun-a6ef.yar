rule TTP_XOR_QUAD_CurrentVersionRun_a6ef {
  strings:
    $key_a6ef = { f5 80 [2] d1 8e [2] fa a2 [2] d4 80 [2] c0 9b [2] cf 81 [2] d1 9c [2] d3 9d [2] c8 9b [2] d4 9c [2] c8 b3 }

  condition:
    any of them
}