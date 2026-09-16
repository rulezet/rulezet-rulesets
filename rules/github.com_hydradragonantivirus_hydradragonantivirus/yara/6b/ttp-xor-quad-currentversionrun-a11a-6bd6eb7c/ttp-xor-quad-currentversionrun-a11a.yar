rule TTP_XOR_QUAD_CurrentVersionRun_a11a {
  strings:
    $key_a11a = { f2 75 [2] d6 7b [2] fd 57 [2] d3 75 [2] c7 6e [2] c8 74 [2] d6 69 [2] d4 68 [2] cf 6e [2] d3 69 [2] cf 46 }

  condition:
    any of them
}