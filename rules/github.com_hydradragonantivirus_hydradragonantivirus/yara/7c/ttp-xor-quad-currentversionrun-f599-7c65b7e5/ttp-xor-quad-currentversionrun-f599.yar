rule TTP_XOR_QUAD_CurrentVersionRun_f599 {
  strings:
    $key_f599 = { a6 f6 [2] 82 f8 [2] a9 d4 [2] 87 f6 [2] 93 ed [2] 9c f7 [2] 82 ea [2] 80 eb [2] 9b ed [2] 87 ea [2] 9b c5 }

  condition:
    any of them
}