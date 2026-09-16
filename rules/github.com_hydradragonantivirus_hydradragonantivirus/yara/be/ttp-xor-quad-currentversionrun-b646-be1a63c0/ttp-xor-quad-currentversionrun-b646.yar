rule TTP_XOR_QUAD_CurrentVersionRun_b646 {
  strings:
    $key_b646 = { e5 29 [2] c1 27 [2] ea 0b [2] c4 29 [2] d0 32 [2] df 28 [2] c1 35 [2] c3 34 [2] d8 32 [2] c4 35 [2] d8 1a }

  condition:
    any of them
}