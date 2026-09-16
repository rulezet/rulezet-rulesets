rule TTP_XOR_QUAD_CurrentVersionRun_b669 {
  strings:
    $key_b669 = { e5 06 [2] c1 08 [2] ea 24 [2] c4 06 [2] d0 1d [2] df 07 [2] c1 1a [2] c3 1b [2] d8 1d [2] c4 1a [2] d8 35 }

  condition:
    any of them
}