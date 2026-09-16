rule TTP_XOR_QUAD_CurrentVersionRun_b614 {
  strings:
    $key_b614 = { e5 7b [2] c1 75 [2] ea 59 [2] c4 7b [2] d0 60 [2] df 7a [2] c1 67 [2] c3 66 [2] d8 60 [2] c4 67 [2] d8 48 }

  condition:
    any of them
}