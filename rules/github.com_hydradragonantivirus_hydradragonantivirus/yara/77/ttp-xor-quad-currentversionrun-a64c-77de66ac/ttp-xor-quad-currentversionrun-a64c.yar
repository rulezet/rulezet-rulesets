rule TTP_XOR_QUAD_CurrentVersionRun_a64c {
  strings:
    $key_a64c = { f5 23 [2] d1 2d [2] fa 01 [2] d4 23 [2] c0 38 [2] cf 22 [2] d1 3f [2] d3 3e [2] c8 38 [2] d4 3f [2] c8 10 }

  condition:
    any of them
}