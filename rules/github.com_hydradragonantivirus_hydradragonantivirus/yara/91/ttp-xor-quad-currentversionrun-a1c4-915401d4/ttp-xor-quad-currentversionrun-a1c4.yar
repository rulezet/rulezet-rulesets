rule TTP_XOR_QUAD_CurrentVersionRun_a1c4 {
  strings:
    $key_a1c4 = { f2 ab [2] d6 a5 [2] fd 89 [2] d3 ab [2] c7 b0 [2] c8 aa [2] d6 b7 [2] d4 b6 [2] cf b0 [2] d3 b7 [2] cf 98 }

  condition:
    any of them
}