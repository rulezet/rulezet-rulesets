rule TTP_XOR_QUAD_CurrentVersionRun_7f99 {
  strings:
    $key_7f99 = { 2c f6 [2] 08 f8 [2] 23 d4 [2] 0d f6 [2] 19 ed [2] 16 f7 [2] 08 ea [2] 0a eb [2] 11 ed [2] 0d ea [2] 11 c5 }

  condition:
    any of them
}