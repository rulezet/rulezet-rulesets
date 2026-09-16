rule TTP_XOR_QUAD_CurrentVersionRun_b652 {
  strings:
    $key_b652 = { e5 3d [2] c1 33 [2] ea 1f [2] c4 3d [2] d0 26 [2] df 3c [2] c1 21 [2] c3 20 [2] d8 26 [2] c4 21 [2] d8 0e }

  condition:
    any of them
}