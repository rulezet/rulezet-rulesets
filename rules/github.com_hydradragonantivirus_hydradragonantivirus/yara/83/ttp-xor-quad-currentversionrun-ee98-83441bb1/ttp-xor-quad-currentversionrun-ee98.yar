rule TTP_XOR_QUAD_CurrentVersionRun_ee98 {
  strings:
    $key_ee98 = { bd f7 [2] 99 f9 [2] b2 d5 [2] 9c f7 [2] 88 ec [2] 87 f6 [2] 99 eb [2] 9b ea [2] 80 ec [2] 9c eb [2] 80 c4 }

  condition:
    any of them
}