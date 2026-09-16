rule TTP_XOR_QUAD_CurrentVersionRun_3a99 {
  strings:
    $key_3a99 = { 69 f6 [2] 4d f8 [2] 66 d4 [2] 48 f6 [2] 5c ed [2] 53 f7 [2] 4d ea [2] 4f eb [2] 54 ed [2] 48 ea [2] 54 c5 }

  condition:
    any of them
}