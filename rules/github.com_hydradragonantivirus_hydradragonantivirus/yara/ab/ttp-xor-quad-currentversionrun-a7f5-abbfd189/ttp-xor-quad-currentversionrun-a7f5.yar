rule TTP_XOR_QUAD_CurrentVersionRun_a7f5 {
  strings:
    $key_a7f5 = { f4 9a [2] d0 94 [2] fb b8 [2] d5 9a [2] c1 81 [2] ce 9b [2] d0 86 [2] d2 87 [2] c9 81 [2] d5 86 [2] c9 a9 }

  condition:
    any of them
}