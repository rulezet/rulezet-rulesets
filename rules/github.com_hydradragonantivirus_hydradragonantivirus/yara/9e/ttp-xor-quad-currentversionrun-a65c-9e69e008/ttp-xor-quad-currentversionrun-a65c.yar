rule TTP_XOR_QUAD_CurrentVersionRun_a65c {
  strings:
    $key_a65c = { f5 33 [2] d1 3d [2] fa 11 [2] d4 33 [2] c0 28 [2] cf 32 [2] d1 2f [2] d3 2e [2] c8 28 [2] d4 2f [2] c8 00 }

  condition:
    any of them
}