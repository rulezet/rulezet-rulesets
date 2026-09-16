rule TTP_XOR_QUAD_CurrentVersionRun_1f99 {
  strings:
    $key_1f99 = { 4c f6 [2] 68 f8 [2] 43 d4 [2] 6d f6 [2] 79 ed [2] 76 f7 [2] 68 ea [2] 6a eb [2] 71 ed [2] 6d ea [2] 71 c5 }

  condition:
    any of them
}