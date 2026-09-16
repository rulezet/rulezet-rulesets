rule TTP_XOR_QUAD_CurrentVersionRun_a7da {
  strings:
    $key_a7da = { f4 b5 [2] d0 bb [2] fb 97 [2] d5 b5 [2] c1 ae [2] ce b4 [2] d0 a9 [2] d2 a8 [2] c9 ae [2] d5 a9 [2] c9 86 }

  condition:
    any of them
}