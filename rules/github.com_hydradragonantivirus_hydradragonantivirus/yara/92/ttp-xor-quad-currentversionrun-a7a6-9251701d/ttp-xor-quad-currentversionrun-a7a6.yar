rule TTP_XOR_QUAD_CurrentVersionRun_a7a6 {
  strings:
    $key_a7a6 = { f4 c9 [2] d0 c7 [2] fb eb [2] d5 c9 [2] c1 d2 [2] ce c8 [2] d0 d5 [2] d2 d4 [2] c9 d2 [2] d5 d5 [2] c9 fa }

  condition:
    any of them
}