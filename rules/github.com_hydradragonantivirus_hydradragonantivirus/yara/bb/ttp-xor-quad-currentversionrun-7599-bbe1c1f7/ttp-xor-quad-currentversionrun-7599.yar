rule TTP_XOR_QUAD_CurrentVersionRun_7599 {
  strings:
    $key_7599 = { 26 f6 [2] 02 f8 [2] 29 d4 [2] 07 f6 [2] 13 ed [2] 1c f7 [2] 02 ea [2] 00 eb [2] 1b ed [2] 07 ea [2] 1b c5 }

  condition:
    any of them
}