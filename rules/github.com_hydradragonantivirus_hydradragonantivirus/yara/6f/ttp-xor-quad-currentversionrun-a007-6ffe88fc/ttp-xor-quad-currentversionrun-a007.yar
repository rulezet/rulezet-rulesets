rule TTP_XOR_QUAD_CurrentVersionRun_a007 {
  strings:
    $key_a007 = { f3 68 [2] d7 66 [2] fc 4a [2] d2 68 [2] c6 73 [2] c9 69 [2] d7 74 [2] d5 75 [2] ce 73 [2] d2 74 [2] ce 5b }

  condition:
    any of them
}