rule TTP_XOR_QUAD_CurrentVersionRun_e599 {
  strings:
    $key_e599 = { b6 f6 [2] 92 f8 [2] b9 d4 [2] 97 f6 [2] 83 ed [2] 8c f7 [2] 92 ea [2] 90 eb [2] 8b ed [2] 97 ea [2] 8b c5 }

  condition:
    any of them
}