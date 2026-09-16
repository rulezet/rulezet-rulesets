rule TTP_XOR_QUAD_CurrentVersionRun_b039 {
  strings:
    $key_b039 = { e3 56 [2] c7 58 [2] ec 74 [2] c2 56 [2] d6 4d [2] d9 57 [2] c7 4a [2] c5 4b [2] de 4d [2] c2 4a [2] de 65 }

  condition:
    any of them
}