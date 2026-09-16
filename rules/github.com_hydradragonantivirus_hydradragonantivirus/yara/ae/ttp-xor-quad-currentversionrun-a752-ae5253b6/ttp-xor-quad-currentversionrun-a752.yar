rule TTP_XOR_QUAD_CurrentVersionRun_a752 {
  strings:
    $key_a752 = { f4 3d [2] d0 33 [2] fb 1f [2] d5 3d [2] c1 26 [2] ce 3c [2] d0 21 [2] d2 20 [2] c9 26 [2] d5 21 [2] c9 0e }

  condition:
    any of them
}