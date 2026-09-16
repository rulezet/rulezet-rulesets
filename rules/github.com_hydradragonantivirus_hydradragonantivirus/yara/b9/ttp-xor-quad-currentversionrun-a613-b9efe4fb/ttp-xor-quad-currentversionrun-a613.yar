rule TTP_XOR_QUAD_CurrentVersionRun_a613 {
  strings:
    $key_a613 = { f5 7c [2] d1 72 [2] fa 5e [2] d4 7c [2] c0 67 [2] cf 7d [2] d1 60 [2] d3 61 [2] c8 67 [2] d4 60 [2] c8 4f }

  condition:
    any of them
}