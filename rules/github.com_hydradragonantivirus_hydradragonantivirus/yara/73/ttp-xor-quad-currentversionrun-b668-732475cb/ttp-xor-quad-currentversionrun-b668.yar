rule TTP_XOR_QUAD_CurrentVersionRun_b668 {
  strings:
    $key_b668 = { e5 07 [2] c1 09 [2] ea 25 [2] c4 07 [2] d0 1c [2] df 06 [2] c1 1b [2] c3 1a [2] d8 1c [2] c4 1b [2] d8 34 }

  condition:
    any of them
}