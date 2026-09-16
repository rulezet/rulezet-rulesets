rule TTP_XOR_QUAD_CurrentVersionRun_a13a {
  strings:
    $key_a13a = { f2 55 [2] d6 5b [2] fd 77 [2] d3 55 [2] c7 4e [2] c8 54 [2] d6 49 [2] d4 48 [2] cf 4e [2] d3 49 [2] cf 66 }

  condition:
    any of them
}