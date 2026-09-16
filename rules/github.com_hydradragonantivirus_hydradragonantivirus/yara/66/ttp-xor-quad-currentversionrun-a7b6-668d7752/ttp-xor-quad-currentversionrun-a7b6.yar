rule TTP_XOR_QUAD_CurrentVersionRun_a7b6 {
  strings:
    $key_a7b6 = { f4 d9 [2] d0 d7 [2] fb fb [2] d5 d9 [2] c1 c2 [2] ce d8 [2] d0 c5 [2] d2 c4 [2] c9 c2 [2] d5 c5 [2] c9 ea }

  condition:
    any of them
}