rule TTP_XOR_QUAD_CurrentVersionRun_3b84 {
  strings:
    $key_3b84 = { 68 eb [2] 4c e5 [2] 67 c9 [2] 49 eb [2] 5d f0 [2] 52 ea [2] 4c f7 [2] 4e f6 [2] 55 f0 [2] 49 f7 [2] 55 d8 }

  condition:
    any of them
}