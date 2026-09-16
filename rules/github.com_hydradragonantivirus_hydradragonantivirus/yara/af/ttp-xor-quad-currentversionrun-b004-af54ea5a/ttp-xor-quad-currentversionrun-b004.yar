rule TTP_XOR_QUAD_CurrentVersionRun_b004 {
  strings:
    $key_b004 = { e3 6b [2] c7 65 [2] ec 49 [2] c2 6b [2] d6 70 [2] d9 6a [2] c7 77 [2] c5 76 [2] de 70 [2] c2 77 [2] de 58 }

  condition:
    any of them
}