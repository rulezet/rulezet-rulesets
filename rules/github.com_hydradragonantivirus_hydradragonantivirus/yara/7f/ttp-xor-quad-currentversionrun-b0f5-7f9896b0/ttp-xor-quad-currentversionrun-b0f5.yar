rule TTP_XOR_QUAD_CurrentVersionRun_b0f5 {
  strings:
    $key_b0f5 = { e3 9a [2] c7 94 [2] ec b8 [2] c2 9a [2] d6 81 [2] d9 9b [2] c7 86 [2] c5 87 [2] de 81 [2] c2 86 [2] de a9 }

  condition:
    any of them
}