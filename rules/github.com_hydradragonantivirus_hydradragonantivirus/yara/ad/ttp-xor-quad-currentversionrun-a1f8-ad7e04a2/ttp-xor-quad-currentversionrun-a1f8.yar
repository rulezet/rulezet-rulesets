rule TTP_XOR_QUAD_CurrentVersionRun_a1f8 {
  strings:
    $key_a1f8 = { f2 97 [2] d6 99 [2] fd b5 [2] d3 97 [2] c7 8c [2] c8 96 [2] d6 8b [2] d4 8a [2] cf 8c [2] d3 8b [2] cf a4 }

  condition:
    any of them
}