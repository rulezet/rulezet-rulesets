rule TTP_XOR_QUAD_CurrentVersionRun_3099 {
  strings:
    $key_3099 = { 63 f6 [2] 47 f8 [2] 6c d4 [2] 42 f6 [2] 56 ed [2] 59 f7 [2] 47 ea [2] 45 eb [2] 5e ed [2] 42 ea [2] 5e c5 }

  condition:
    any of them
}