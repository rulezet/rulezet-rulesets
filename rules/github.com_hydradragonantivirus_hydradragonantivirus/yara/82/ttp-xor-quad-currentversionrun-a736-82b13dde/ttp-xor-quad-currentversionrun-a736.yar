rule TTP_XOR_QUAD_CurrentVersionRun_a736 {
  strings:
    $key_a736 = { f4 59 [2] d0 57 [2] fb 7b [2] d5 59 [2] c1 42 [2] ce 58 [2] d0 45 [2] d2 44 [2] c9 42 [2] d5 45 [2] c9 6a }

  condition:
    any of them
}