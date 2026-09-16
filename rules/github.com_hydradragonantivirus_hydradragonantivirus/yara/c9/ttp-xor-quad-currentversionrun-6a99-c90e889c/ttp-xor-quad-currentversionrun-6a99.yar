rule TTP_XOR_QUAD_CurrentVersionRun_6a99 {
  strings:
    $key_6a99 = { 39 f6 [2] 1d f8 [2] 36 d4 [2] 18 f6 [2] 0c ed [2] 03 f7 [2] 1d ea [2] 1f eb [2] 04 ed [2] 18 ea [2] 04 c5 }

  condition:
    any of them
}