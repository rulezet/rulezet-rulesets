rule TTP_XOR_QUAD_CurrentVersionRun_a7e9 {
  strings:
    $key_a7e9 = { f4 86 [2] d0 88 [2] fb a4 [2] d5 86 [2] c1 9d [2] ce 87 [2] d0 9a [2] d2 9b [2] c9 9d [2] d5 9a [2] c9 b5 }

  condition:
    any of them
}