rule TTP_XOR_QUAD_CurrentVersionRun_a74e {
  strings:
    $key_a74e = { f4 21 [2] d0 2f [2] fb 03 [2] d5 21 [2] c1 3a [2] ce 20 [2] d0 3d [2] d2 3c [2] c9 3a [2] d5 3d [2] c9 12 }

  condition:
    any of them
}