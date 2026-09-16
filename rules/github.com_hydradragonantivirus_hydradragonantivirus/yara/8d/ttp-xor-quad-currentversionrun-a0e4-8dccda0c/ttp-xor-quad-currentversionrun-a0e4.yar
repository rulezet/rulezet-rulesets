rule TTP_XOR_QUAD_CurrentVersionRun_a0e4 {
  strings:
    $key_a0e4 = { f3 8b [2] d7 85 [2] fc a9 [2] d2 8b [2] c6 90 [2] c9 8a [2] d7 97 [2] d5 96 [2] ce 90 [2] d2 97 [2] ce b8 }

  condition:
    any of them
}