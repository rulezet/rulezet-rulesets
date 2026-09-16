rule TTP_XOR_QUAD_CurrentVersionRun_7a99 {
  strings:
    $key_7a99 = { 29 f6 [2] 0d f8 [2] 26 d4 [2] 08 f6 [2] 1c ed [2] 13 f7 [2] 0d ea [2] 0f eb [2] 14 ed [2] 08 ea [2] 14 c5 }

  condition:
    any of them
}