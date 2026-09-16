rule TTP_XOR_QUAD_CurrentVersionRun_a1c8 {
  strings:
    $key_a1c8 = { f2 a7 [2] d6 a9 [2] fd 85 [2] d3 a7 [2] c7 bc [2] c8 a6 [2] d6 bb [2] d4 ba [2] cf bc [2] d3 bb [2] cf 94 }

  condition:
    any of them
}