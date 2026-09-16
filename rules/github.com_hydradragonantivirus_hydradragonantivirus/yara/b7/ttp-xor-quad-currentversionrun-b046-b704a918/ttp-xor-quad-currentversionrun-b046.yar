rule TTP_XOR_QUAD_CurrentVersionRun_b046 {
  strings:
    $key_b046 = { e3 29 [2] c7 27 [2] ec 0b [2] c2 29 [2] d6 32 [2] d9 28 [2] c7 35 [2] c5 34 [2] de 32 [2] c2 35 [2] de 1a }

  condition:
    any of them
}