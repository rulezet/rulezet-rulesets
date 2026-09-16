rule TTP_XOR_QUAD_CurrentVersionRun_0599 {
  strings:
    $key_0599 = { 56 f6 [2] 72 f8 [2] 59 d4 [2] 77 f6 [2] 63 ed [2] 6c f7 [2] 72 ea [2] 70 eb [2] 6b ed [2] 77 ea [2] 6b c5 }

  condition:
    any of them
}