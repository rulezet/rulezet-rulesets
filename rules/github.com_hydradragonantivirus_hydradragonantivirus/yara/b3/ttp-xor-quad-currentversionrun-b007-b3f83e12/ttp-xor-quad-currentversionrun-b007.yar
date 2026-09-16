rule TTP_XOR_QUAD_CurrentVersionRun_b007 {
  strings:
    $key_b007 = { e3 68 [2] c7 66 [2] ec 4a [2] c2 68 [2] d6 73 [2] d9 69 [2] c7 74 [2] c5 75 [2] de 73 [2] c2 74 [2] de 5b }

  condition:
    any of them
}