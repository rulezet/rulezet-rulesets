rule TTP_XOR_QUAD_CurrentVersionRun_a118 {
  strings:
    $key_a118 = { f2 77 [2] d6 79 [2] fd 55 [2] d3 77 [2] c7 6c [2] c8 76 [2] d6 6b [2] d4 6a [2] cf 6c [2] d3 6b [2] cf 44 }

  condition:
    any of them
}