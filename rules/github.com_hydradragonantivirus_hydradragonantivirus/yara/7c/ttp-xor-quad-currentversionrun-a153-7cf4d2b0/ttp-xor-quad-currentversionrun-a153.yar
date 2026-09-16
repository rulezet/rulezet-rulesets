rule TTP_XOR_QUAD_CurrentVersionRun_a153 {
  strings:
    $key_a153 = { f2 3c [2] d6 32 [2] fd 1e [2] d3 3c [2] c7 27 [2] c8 3d [2] d6 20 [2] d4 21 [2] cf 27 [2] d3 20 [2] cf 0f }

  condition:
    any of them
}