rule TTP_XOR_QUAD_CurrentVersionRun_a725 {
  strings:
    $key_a725 = { f4 4a [2] d0 44 [2] fb 68 [2] d5 4a [2] c1 51 [2] ce 4b [2] d0 56 [2] d2 57 [2] c9 51 [2] d5 56 [2] c9 79 }

  condition:
    any of them
}