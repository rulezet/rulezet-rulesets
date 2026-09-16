rule TTP_XOR_QUAD_CurrentVersionRun_b0e5 {
  strings:
    $key_b0e5 = { e3 8a [2] c7 84 [2] ec a8 [2] c2 8a [2] d6 91 [2] d9 8b [2] c7 96 [2] c5 97 [2] de 91 [2] c2 96 [2] de b9 }

  condition:
    any of them
}