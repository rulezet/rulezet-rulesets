rule TTP_XOR_QUAD_CurrentVersionRun_a748 {
  strings:
    $key_a748 = { f4 27 [2] d0 29 [2] fb 05 [2] d5 27 [2] c1 3c [2] ce 26 [2] d0 3b [2] d2 3a [2] c9 3c [2] d5 3b [2] c9 14 }

  condition:
    any of them
}