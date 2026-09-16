rule TTP_XOR_QUAD_CurrentVersionRun_a131 {
  strings:
    $key_a131 = { f2 5e [2] d6 50 [2] fd 7c [2] d3 5e [2] c7 45 [2] c8 5f [2] d6 42 [2] d4 43 [2] cf 45 [2] d3 42 [2] cf 6d }

  condition:
    any of them
}