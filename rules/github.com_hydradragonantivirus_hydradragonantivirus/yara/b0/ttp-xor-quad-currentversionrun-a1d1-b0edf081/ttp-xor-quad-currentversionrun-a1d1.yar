rule TTP_XOR_QUAD_CurrentVersionRun_a1d1 {
  strings:
    $key_a1d1 = { f2 be [2] d6 b0 [2] fd 9c [2] d3 be [2] c7 a5 [2] c8 bf [2] d6 a2 [2] d4 a3 [2] cf a5 [2] d3 a2 [2] cf 8d }

  condition:
    any of them
}