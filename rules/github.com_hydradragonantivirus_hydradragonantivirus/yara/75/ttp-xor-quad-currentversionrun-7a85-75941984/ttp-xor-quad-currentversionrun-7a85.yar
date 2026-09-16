rule TTP_XOR_QUAD_CurrentVersionRun_7a85 {
  strings:
    $key_7a85 = { 29 ea [2] 0d e4 [2] 26 c8 [2] 08 ea [2] 1c f1 [2] 13 eb [2] 0d f6 [2] 0f f7 [2] 14 f1 [2] 08 f6 [2] 14 d9 }

  condition:
    any of them
}