rule TTP_XOR_QUAD_CurrentVersionRun_a67c {
  strings:
    $key_a67c = { f5 13 [2] d1 1d [2] fa 31 [2] d4 13 [2] c0 08 [2] cf 12 [2] d1 0f [2] d3 0e [2] c8 08 [2] d4 0f [2] c8 20 }

  condition:
    any of them
}