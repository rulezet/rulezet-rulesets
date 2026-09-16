rule TTP_XOR_QUAD_CurrentVersionRun_b658 {
  strings:
    $key_b658 = { e5 37 [2] c1 39 [2] ea 15 [2] c4 37 [2] d0 2c [2] df 36 [2] c1 2b [2] c3 2a [2] d8 2c [2] c4 2b [2] d8 04 }

  condition:
    any of them
}