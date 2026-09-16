rule TTP_XOR_QUAD_CurrentVersionRun_0984 {
  strings:
    $key_0984 = { 5a eb [2] 7e e5 [2] 55 c9 [2] 7b eb [2] 6f f0 [2] 60 ea [2] 7e f7 [2] 7c f6 [2] 67 f0 [2] 7b f7 [2] 67 d8 }

  condition:
    any of them
}