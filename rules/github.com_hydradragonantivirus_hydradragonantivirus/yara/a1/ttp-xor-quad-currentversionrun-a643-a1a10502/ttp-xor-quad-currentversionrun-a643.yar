rule TTP_XOR_QUAD_CurrentVersionRun_a643 {
  strings:
    $key_a643 = { f5 2c [2] d1 22 [2] fa 0e [2] d4 2c [2] c0 37 [2] cf 2d [2] d1 30 [2] d3 31 [2] c8 37 [2] d4 30 [2] c8 1f }

  condition:
    any of them
}