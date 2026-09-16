rule TTP_XOR_QUAD_CurrentVersionRun_a0e8 {
  strings:
    $key_a0e8 = { f3 87 [2] d7 89 [2] fc a5 [2] d2 87 [2] c6 9c [2] c9 86 [2] d7 9b [2] d5 9a [2] ce 9c [2] d2 9b [2] ce b4 }

  condition:
    any of them
}