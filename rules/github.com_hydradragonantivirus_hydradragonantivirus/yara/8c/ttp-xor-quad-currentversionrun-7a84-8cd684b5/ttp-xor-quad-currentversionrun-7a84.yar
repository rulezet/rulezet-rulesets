rule TTP_XOR_QUAD_CurrentVersionRun_7a84 {
  strings:
    $key_7a84 = { 29 eb [2] 0d e5 [2] 26 c9 [2] 08 eb [2] 1c f0 [2] 13 ea [2] 0d f7 [2] 0f f6 [2] 14 f0 [2] 08 f7 [2] 14 d8 }

  condition:
    any of them
}