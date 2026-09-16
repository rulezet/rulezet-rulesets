rule TTP_XOR_QUAD_CurrentVersionRun_4898 {
  strings:
    $key_4898 = { 1b f7 [2] 3f f9 [2] 14 d5 [2] 3a f7 [2] 2e ec [2] 21 f6 [2] 3f eb [2] 3d ea [2] 26 ec [2] 3a eb [2] 26 c4 }

  condition:
    any of them
}