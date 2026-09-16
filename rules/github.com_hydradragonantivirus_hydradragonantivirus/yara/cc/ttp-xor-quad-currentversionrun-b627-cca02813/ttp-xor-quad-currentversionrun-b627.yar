rule TTP_XOR_QUAD_CurrentVersionRun_b627 {
  strings:
    $key_b627 = { e5 48 [2] c1 46 [2] ea 6a [2] c4 48 [2] d0 53 [2] df 49 [2] c1 54 [2] c3 55 [2] d8 53 [2] c4 54 [2] d8 7b }

  condition:
    any of them
}