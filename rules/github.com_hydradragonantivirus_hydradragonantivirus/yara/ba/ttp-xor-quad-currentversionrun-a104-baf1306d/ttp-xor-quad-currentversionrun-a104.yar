rule TTP_XOR_QUAD_CurrentVersionRun_a104 {
  strings:
    $key_a104 = { f2 6b [2] d6 65 [2] fd 49 [2] d3 6b [2] c7 70 [2] c8 6a [2] d6 77 [2] d4 76 [2] cf 70 [2] d3 77 [2] cf 58 }

  condition:
    any of them
}