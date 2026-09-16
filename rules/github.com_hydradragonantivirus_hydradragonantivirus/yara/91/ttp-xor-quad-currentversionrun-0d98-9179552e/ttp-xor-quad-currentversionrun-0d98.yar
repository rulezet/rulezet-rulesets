rule TTP_XOR_QUAD_CurrentVersionRun_0d98 {
  strings:
    $key_0d98 = { 5e f7 [2] 7a f9 [2] 51 d5 [2] 7f f7 [2] 6b ec [2] 64 f6 [2] 7a eb [2] 78 ea [2] 63 ec [2] 7f eb [2] 63 c4 }

  condition:
    any of them
}