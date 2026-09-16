rule TTP_XOR_QUAD_CurrentVersionRun_a707 {
  strings:
    $key_a707 = { f4 68 [2] d0 66 [2] fb 4a [2] d5 68 [2] c1 73 [2] ce 69 [2] d0 74 [2] d2 75 [2] c9 73 [2] d5 74 [2] c9 5b }

  condition:
    any of them
}