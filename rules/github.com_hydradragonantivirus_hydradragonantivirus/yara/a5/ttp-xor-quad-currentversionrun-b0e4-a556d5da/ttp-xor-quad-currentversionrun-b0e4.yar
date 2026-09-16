rule TTP_XOR_QUAD_CurrentVersionRun_b0e4 {
  strings:
    $key_b0e4 = { e3 8b [2] c7 85 [2] ec a9 [2] c2 8b [2] d6 90 [2] d9 8a [2] c7 97 [2] c5 96 [2] de 90 [2] c2 97 [2] de b8 }

  condition:
    any of them
}