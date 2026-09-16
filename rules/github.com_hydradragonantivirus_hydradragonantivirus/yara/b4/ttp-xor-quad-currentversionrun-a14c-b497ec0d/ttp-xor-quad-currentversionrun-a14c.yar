rule TTP_XOR_QUAD_CurrentVersionRun_a14c {
  strings:
    $key_a14c = { f2 23 [2] d6 2d [2] fd 01 [2] d3 23 [2] c7 38 [2] c8 22 [2] d6 3f [2] d4 3e [2] cf 38 [2] d3 3f [2] cf 10 }

  condition:
    any of them
}