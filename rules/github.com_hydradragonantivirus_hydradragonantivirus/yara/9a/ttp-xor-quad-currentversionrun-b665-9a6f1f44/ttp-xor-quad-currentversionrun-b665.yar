rule TTP_XOR_QUAD_CurrentVersionRun_b665 {
  strings:
    $key_b665 = { e5 0a [2] c1 04 [2] ea 28 [2] c4 0a [2] d0 11 [2] df 0b [2] c1 16 [2] c3 17 [2] d8 11 [2] c4 16 [2] d8 39 }

  condition:
    any of them
}