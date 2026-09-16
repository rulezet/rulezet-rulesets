rule TTP_XOR_QUAD_CurrentVersionRun_a122 {
  strings:
    $key_a122 = { f2 4d [2] d6 43 [2] fd 6f [2] d3 4d [2] c7 56 [2] c8 4c [2] d6 51 [2] d4 50 [2] cf 56 [2] d3 51 [2] cf 7e }

  condition:
    any of them
}