rule TTP_XOR_QUAD_CurrentVersionRun_b647 {
  strings:
    $key_b647 = { e5 28 [2] c1 26 [2] ea 0a [2] c4 28 [2] d0 33 [2] df 29 [2] c1 34 [2] c3 35 [2] d8 33 [2] c4 34 [2] d8 1b }

  condition:
    any of them
}