rule TTP_XOR_QUAD_CurrentVersionRun_a1e0 {
  strings:
    $key_a1e0 = { f2 8f [2] d6 81 [2] fd ad [2] d3 8f [2] c7 94 [2] c8 8e [2] d6 93 [2] d4 92 [2] cf 94 [2] d3 93 [2] cf bc }

  condition:
    any of them
}