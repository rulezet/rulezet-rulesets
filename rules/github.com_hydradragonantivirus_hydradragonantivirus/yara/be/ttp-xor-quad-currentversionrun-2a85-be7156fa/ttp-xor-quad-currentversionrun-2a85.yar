rule TTP_XOR_QUAD_CurrentVersionRun_2a85 {
  strings:
    $key_2a85 = { 79 ea [2] 5d e4 [2] 76 c8 [2] 58 ea [2] 4c f1 [2] 43 eb [2] 5d f6 [2] 5f f7 [2] 44 f1 [2] 58 f6 [2] 44 d9 }

  condition:
    any of them
}