rule TTP_XOR_QUAD_CurrentVersionRun_a67d {
  strings:
    $key_a67d = { f5 12 [2] d1 1c [2] fa 30 [2] d4 12 [2] c0 09 [2] cf 13 [2] d1 0e [2] d3 0f [2] c8 09 [2] d4 0e [2] c8 21 }

  condition:
    any of them
}