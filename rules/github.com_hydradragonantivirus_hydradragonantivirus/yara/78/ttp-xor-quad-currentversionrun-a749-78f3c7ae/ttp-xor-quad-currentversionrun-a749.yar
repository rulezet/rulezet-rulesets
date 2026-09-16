rule TTP_XOR_QUAD_CurrentVersionRun_a749 {
  strings:
    $key_a749 = { f4 26 [2] d0 28 [2] fb 04 [2] d5 26 [2] c1 3d [2] ce 27 [2] d0 3a [2] d2 3b [2] c9 3d [2] d5 3a [2] c9 15 }

  condition:
    any of them
}