rule TTP_XOR_QUAD_CurrentVersionRun_0099 {
  strings:
    $key_0099 = { 53 f6 [2] 77 f8 [2] 5c d4 [2] 72 f6 [2] 66 ed [2] 69 f7 [2] 77 ea [2] 75 eb [2] 6e ed [2] 72 ea [2] 6e c5 }

  condition:
    any of them
}