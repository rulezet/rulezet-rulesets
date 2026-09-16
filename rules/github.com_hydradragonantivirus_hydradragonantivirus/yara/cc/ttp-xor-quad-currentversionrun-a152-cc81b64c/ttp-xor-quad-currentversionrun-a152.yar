rule TTP_XOR_QUAD_CurrentVersionRun_a152 {
  strings:
    $key_a152 = { f2 3d [2] d6 33 [2] fd 1f [2] d3 3d [2] c7 26 [2] c8 3c [2] d6 21 [2] d4 20 [2] cf 26 [2] d3 21 [2] cf 0e }

  condition:
    any of them
}