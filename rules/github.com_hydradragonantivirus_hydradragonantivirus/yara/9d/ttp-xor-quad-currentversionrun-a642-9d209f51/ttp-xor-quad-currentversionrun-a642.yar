rule TTP_XOR_QUAD_CurrentVersionRun_a642 {
  strings:
    $key_a642 = { f5 2d [2] d1 23 [2] fa 0f [2] d4 2d [2] c0 36 [2] cf 2c [2] d1 31 [2] d3 30 [2] c8 36 [2] d4 31 [2] c8 1e }

  condition:
    any of them
}