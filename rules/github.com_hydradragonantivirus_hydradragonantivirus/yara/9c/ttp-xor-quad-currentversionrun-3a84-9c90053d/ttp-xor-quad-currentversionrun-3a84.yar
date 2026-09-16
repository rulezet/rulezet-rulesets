rule TTP_XOR_QUAD_CurrentVersionRun_3a84 {
  strings:
    $key_3a84 = { 69 eb [2] 4d e5 [2] 66 c9 [2] 48 eb [2] 5c f0 [2] 53 ea [2] 4d f7 [2] 4f f6 [2] 54 f0 [2] 48 f7 [2] 54 d8 }

  condition:
    any of them
}