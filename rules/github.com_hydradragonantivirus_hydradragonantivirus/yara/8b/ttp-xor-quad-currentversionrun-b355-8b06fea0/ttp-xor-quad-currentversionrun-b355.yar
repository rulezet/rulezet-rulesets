rule TTP_XOR_QUAD_CurrentVersionRun_b355 {
  strings:
    $key_b355 = { e0 3a [2] c4 34 [2] ef 18 [2] c1 3a [2] d5 21 [2] da 3b [2] c4 26 [2] c6 27 [2] dd 21 [2] c1 26 [2] dd 09 }

  condition:
    any of them
}