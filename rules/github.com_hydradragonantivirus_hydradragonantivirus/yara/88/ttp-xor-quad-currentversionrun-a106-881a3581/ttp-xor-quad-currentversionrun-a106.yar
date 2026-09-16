rule TTP_XOR_QUAD_CurrentVersionRun_a106 {
  strings:
    $key_a106 = { f2 69 [2] d6 67 [2] fd 4b [2] d3 69 [2] c7 72 [2] c8 68 [2] d6 75 [2] d4 74 [2] cf 72 [2] d3 75 [2] cf 5a }

  condition:
    any of them
}