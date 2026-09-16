rule TTP_XOR_QUAD_CurrentVersionRun_b638 {
  strings:
    $key_b638 = { e5 57 [2] c1 59 [2] ea 75 [2] c4 57 [2] d0 4c [2] df 56 [2] c1 4b [2] c3 4a [2] d8 4c [2] c4 4b [2] d8 64 }

  condition:
    any of them
}