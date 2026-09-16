rule TTP_XOR_QUAD_CurrentVersionRun_0a99 {
  strings:
    $key_0a99 = { 59 f6 [2] 7d f8 [2] 56 d4 [2] 78 f6 [2] 6c ed [2] 63 f7 [2] 7d ea [2] 7f eb [2] 64 ed [2] 78 ea [2] 64 c5 }

  condition:
    any of them
}