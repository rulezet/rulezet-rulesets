rule TTP_XOR_QUAD_CurrentVersionRun_b664 {
  strings:
    $key_b664 = { e5 0b [2] c1 05 [2] ea 29 [2] c4 0b [2] d0 10 [2] df 0a [2] c1 17 [2] c3 16 [2] d8 10 [2] c4 17 [2] d8 38 }

  condition:
    any of them
}