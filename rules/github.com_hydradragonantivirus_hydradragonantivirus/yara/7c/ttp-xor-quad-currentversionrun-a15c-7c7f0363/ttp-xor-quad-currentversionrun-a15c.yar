rule TTP_XOR_QUAD_CurrentVersionRun_a15c {
  strings:
    $key_a15c = { f2 33 [2] d6 3d [2] fd 11 [2] d3 33 [2] c7 28 [2] c8 32 [2] d6 2f [2] d4 2e [2] cf 28 [2] d3 2f [2] cf 00 }

  condition:
    any of them
}