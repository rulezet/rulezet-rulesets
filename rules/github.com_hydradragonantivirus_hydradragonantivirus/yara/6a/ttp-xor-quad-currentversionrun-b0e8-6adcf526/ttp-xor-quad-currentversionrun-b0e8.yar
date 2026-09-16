rule TTP_XOR_QUAD_CurrentVersionRun_b0e8 {
  strings:
    $key_b0e8 = { e3 87 [2] c7 89 [2] ec a5 [2] c2 87 [2] d6 9c [2] d9 86 [2] c7 9b [2] c5 9a [2] de 9c [2] c2 9b [2] de b4 }

  condition:
    any of them
}