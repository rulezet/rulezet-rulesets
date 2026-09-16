rule TTP_XOR_QUAD_CurrentVersionRun_b609 {
  strings:
    $key_b609 = { e5 66 [2] c1 68 [2] ea 44 [2] c4 66 [2] d0 7d [2] df 67 [2] c1 7a [2] c3 7b [2] d8 7d [2] c4 7a [2] d8 55 }

  condition:
    any of them
}