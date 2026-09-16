rule TTP_XOR_QUAD_CurrentVersionRun_a7e5 {
  strings:
    $key_a7e5 = { f4 8a [2] d0 84 [2] fb a8 [2] d5 8a [2] c1 91 [2] ce 8b [2] d0 96 [2] d2 97 [2] c9 91 [2] d5 96 [2] c9 b9 }

  condition:
    any of them
}