rule TTP_XOR_QUAD_CurrentVersionRun_0f99 {
  strings:
    $key_0f99 = { 5c f6 [2] 78 f8 [2] 53 d4 [2] 7d f6 [2] 69 ed [2] 66 f7 [2] 78 ea [2] 7a eb [2] 61 ed [2] 7d ea [2] 61 c5 }

  condition:
    any of them
}