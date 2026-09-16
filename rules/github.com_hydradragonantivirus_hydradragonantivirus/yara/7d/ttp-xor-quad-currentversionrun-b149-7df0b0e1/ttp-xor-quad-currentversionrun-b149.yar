rule TTP_XOR_QUAD_CurrentVersionRun_b149 {
  strings:
    $key_b149 = { e2 26 [2] c6 28 [2] ed 04 [2] c3 26 [2] d7 3d [2] d8 27 [2] c6 3a [2] c4 3b [2] df 3d [2] c3 3a [2] df 15 }

  condition:
    any of them
}