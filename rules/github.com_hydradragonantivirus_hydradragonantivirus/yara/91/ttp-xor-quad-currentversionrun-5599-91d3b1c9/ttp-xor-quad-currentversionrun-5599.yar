rule TTP_XOR_QUAD_CurrentVersionRun_5599 {
  strings:
    $key_5599 = { 06 f6 [2] 22 f8 [2] 09 d4 [2] 27 f6 [2] 33 ed [2] 3c f7 [2] 22 ea [2] 20 eb [2] 3b ed [2] 27 ea [2] 3b c5 }

  condition:
    any of them
}