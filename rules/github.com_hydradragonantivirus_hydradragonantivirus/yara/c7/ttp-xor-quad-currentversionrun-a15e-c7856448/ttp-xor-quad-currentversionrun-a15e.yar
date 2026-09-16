rule TTP_XOR_QUAD_CurrentVersionRun_a15e {
  strings:
    $key_a15e = { f2 31 [2] d6 3f [2] fd 13 [2] d3 31 [2] c7 2a [2] c8 30 [2] d6 2d [2] d4 2c [2] cf 2a [2] d3 2d [2] cf 02 }

  condition:
    any of them
}