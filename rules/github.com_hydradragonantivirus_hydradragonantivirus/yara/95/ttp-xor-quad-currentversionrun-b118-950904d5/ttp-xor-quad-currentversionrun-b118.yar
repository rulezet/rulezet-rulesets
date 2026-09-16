rule TTP_XOR_QUAD_CurrentVersionRun_b118 {
  strings:
    $key_b118 = { e2 77 [2] c6 79 [2] ed 55 [2] c3 77 [2] d7 6c [2] d8 76 [2] c6 6b [2] c4 6a [2] df 6c [2] c3 6b [2] df 44 }

  condition:
    any of them
}