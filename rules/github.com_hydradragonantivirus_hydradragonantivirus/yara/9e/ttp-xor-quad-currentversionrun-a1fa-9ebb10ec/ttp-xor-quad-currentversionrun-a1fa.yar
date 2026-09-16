rule TTP_XOR_QUAD_CurrentVersionRun_a1fa {
  strings:
    $key_a1fa = { f2 95 [2] d6 9b [2] fd b7 [2] d3 95 [2] c7 8e [2] c8 94 [2] d6 89 [2] d4 88 [2] cf 8e [2] d3 89 [2] cf a6 }

  condition:
    any of them
}