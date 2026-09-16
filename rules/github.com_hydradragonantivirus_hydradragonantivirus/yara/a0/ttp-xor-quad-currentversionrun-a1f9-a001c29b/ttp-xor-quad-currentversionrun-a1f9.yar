rule TTP_XOR_QUAD_CurrentVersionRun_a1f9 {
  strings:
    $key_a1f9 = { f2 96 [2] d6 98 [2] fd b4 [2] d3 96 [2] c7 8d [2] c8 97 [2] d6 8a [2] d4 8b [2] cf 8d [2] d3 8a [2] cf a5 }

  condition:
    any of them
}