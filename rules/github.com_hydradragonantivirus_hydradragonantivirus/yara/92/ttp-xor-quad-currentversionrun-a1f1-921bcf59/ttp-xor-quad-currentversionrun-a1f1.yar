rule TTP_XOR_QUAD_CurrentVersionRun_a1f1 {
  strings:
    $key_a1f1 = { f2 9e [2] d6 90 [2] fd bc [2] d3 9e [2] c7 85 [2] c8 9f [2] d6 82 [2] d4 83 [2] cf 85 [2] d3 82 [2] cf ad }

  condition:
    any of them
}