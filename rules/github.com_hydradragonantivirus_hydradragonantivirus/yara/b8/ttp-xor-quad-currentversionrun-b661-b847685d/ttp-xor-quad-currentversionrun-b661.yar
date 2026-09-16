rule TTP_XOR_QUAD_CurrentVersionRun_b661 {
  strings:
    $key_b661 = { e5 0e [2] c1 00 [2] ea 2c [2] c4 0e [2] d0 15 [2] df 0f [2] c1 12 [2] c3 13 [2] d8 15 [2] c4 12 [2] d8 3d }

  condition:
    any of them
}