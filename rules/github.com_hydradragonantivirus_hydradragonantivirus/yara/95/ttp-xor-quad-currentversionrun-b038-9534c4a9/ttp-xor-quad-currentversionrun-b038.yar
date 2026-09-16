rule TTP_XOR_QUAD_CurrentVersionRun_b038 {
  strings:
    $key_b038 = { e3 57 [2] c7 59 [2] ec 75 [2] c2 57 [2] d6 4c [2] d9 56 [2] c7 4b [2] c5 4a [2] de 4c [2] c2 4b [2] de 64 }

  condition:
    any of them
}