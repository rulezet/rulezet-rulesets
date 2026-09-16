rule TTP_XOR_QUAD_CurrentVersionRun_b0fa {
  strings:
    $key_b0fa = { e3 95 [2] c7 9b [2] ec b7 [2] c2 95 [2] d6 8e [2] d9 94 [2] c7 89 [2] c5 88 [2] de 8e [2] c2 89 [2] de a6 }

  condition:
    any of them
}