rule TTP_XOR_QUAD_CurrentVersionRun_a661 {
  strings:
    $key_a661 = { f5 0e [2] d1 00 [2] fa 2c [2] d4 0e [2] c0 15 [2] cf 0f [2] d1 12 [2] d3 13 [2] c8 15 [2] d4 12 [2] c8 3d }

  condition:
    any of them
}