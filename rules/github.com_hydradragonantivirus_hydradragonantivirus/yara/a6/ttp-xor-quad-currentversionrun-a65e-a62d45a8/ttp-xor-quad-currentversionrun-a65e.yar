rule TTP_XOR_QUAD_CurrentVersionRun_a65e {
  strings:
    $key_a65e = { f5 31 [2] d1 3f [2] fa 13 [2] d4 31 [2] c0 2a [2] cf 30 [2] d1 2d [2] d3 2c [2] c8 2a [2] d4 2d [2] c8 02 }

  condition:
    any of them
}