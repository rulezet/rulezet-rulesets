rule TTP_XOR_QUAD_CurrentVersionRun_b62b {
  strings:
    $key_b62b = { e5 44 [2] c1 4a [2] ea 66 [2] c4 44 [2] d0 5f [2] df 45 [2] c1 58 [2] c3 59 [2] d8 5f [2] c4 58 [2] d8 77 }

  condition:
    any of them
}