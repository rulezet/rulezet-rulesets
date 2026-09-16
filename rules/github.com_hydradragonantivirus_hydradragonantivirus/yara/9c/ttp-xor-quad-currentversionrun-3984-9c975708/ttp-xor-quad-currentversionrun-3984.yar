rule TTP_XOR_QUAD_CurrentVersionRun_3984 {
  strings:
    $key_3984 = { 6a eb [2] 4e e5 [2] 65 c9 [2] 4b eb [2] 5f f0 [2] 50 ea [2] 4e f7 [2] 4c f6 [2] 57 f0 [2] 4b f7 [2] 57 d8 }

  condition:
    any of them
}