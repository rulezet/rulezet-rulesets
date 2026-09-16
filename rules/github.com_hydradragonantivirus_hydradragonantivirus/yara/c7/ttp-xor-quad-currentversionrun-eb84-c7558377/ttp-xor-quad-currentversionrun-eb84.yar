rule TTP_XOR_QUAD_CurrentVersionRun_eb84 {
  strings:
    $key_eb84 = { b8 eb [2] 9c e5 [2] b7 c9 [2] 99 eb [2] 8d f0 [2] 82 ea [2] 9c f7 [2] 9e f6 [2] 85 f0 [2] 99 f7 [2] 85 d8 }

  condition:
    any of them
}