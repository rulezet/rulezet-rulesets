rule TTP_XOR_QUAD_CurrentVersionRun_a724 {
  strings:
    $key_a724 = { f4 4b [2] d0 45 [2] fb 69 [2] d5 4b [2] c1 50 [2] ce 4a [2] d0 57 [2] d2 56 [2] c9 50 [2] d5 57 [2] c9 78 }

  condition:
    any of them
}