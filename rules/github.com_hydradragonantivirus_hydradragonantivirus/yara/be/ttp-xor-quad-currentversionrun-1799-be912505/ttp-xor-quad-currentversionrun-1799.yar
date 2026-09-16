rule TTP_XOR_QUAD_CurrentVersionRun_1799 {
  strings:
    $key_1799 = { 44 f6 [2] 60 f8 [2] 4b d4 [2] 65 f6 [2] 71 ed [2] 7e f7 [2] 60 ea [2] 62 eb [2] 79 ed [2] 65 ea [2] 79 c5 }

  condition:
    any of them
}