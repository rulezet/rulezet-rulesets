rule TTP_XOR_QUAD_CurrentVersionRun_5099 {
  strings:
    $key_5099 = { 03 f6 [2] 27 f8 [2] 0c d4 [2] 22 f6 [2] 36 ed [2] 39 f7 [2] 27 ea [2] 25 eb [2] 3e ed [2] 22 ea [2] 3e c5 }

  condition:
    any of them
}