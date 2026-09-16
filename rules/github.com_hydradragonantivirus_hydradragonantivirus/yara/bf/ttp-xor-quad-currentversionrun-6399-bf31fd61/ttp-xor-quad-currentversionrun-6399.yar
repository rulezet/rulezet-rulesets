rule TTP_XOR_QUAD_CurrentVersionRun_6399 {
  strings:
    $key_6399 = { 30 f6 [2] 14 f8 [2] 3f d4 [2] 11 f6 [2] 05 ed [2] 0a f7 [2] 14 ea [2] 16 eb [2] 0d ed [2] 11 ea [2] 0d c5 }

  condition:
    any of them
}