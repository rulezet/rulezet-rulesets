rule TTP_XOR_QUAD_CurrentVersionRun_2984 {
  strings:
    $key_2984 = { 7a eb [2] 5e e5 [2] 75 c9 [2] 5b eb [2] 4f f0 [2] 40 ea [2] 5e f7 [2] 5c f6 [2] 47 f0 [2] 5b f7 [2] 47 d8 }

  condition:
    any of them
}