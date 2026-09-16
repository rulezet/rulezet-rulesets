rule TTP_XOR_QUAD_CurrentVersionRun_b0c7 {
  strings:
    $key_b0c7 = { e3 a8 [2] c7 a6 [2] ec 8a [2] c2 a8 [2] d6 b3 [2] d9 a9 [2] c7 b4 [2] c5 b5 [2] de b3 [2] c2 b4 [2] de 9b }

  condition:
    any of them
}