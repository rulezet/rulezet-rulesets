rule TTP_XOR_QUAD_CurrentVersionRun_b674 {
  strings:
    $key_b674 = { e5 1b [2] c1 15 [2] ea 39 [2] c4 1b [2] d0 00 [2] df 1a [2] c1 07 [2] c3 06 [2] d8 00 [2] c4 07 [2] d8 28 }

  condition:
    any of them
}