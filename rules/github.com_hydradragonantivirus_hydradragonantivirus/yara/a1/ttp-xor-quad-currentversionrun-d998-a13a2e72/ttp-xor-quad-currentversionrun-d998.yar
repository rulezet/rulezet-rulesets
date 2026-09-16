rule TTP_XOR_QUAD_CurrentVersionRun_d998 {
  strings:
    $key_d998 = { 8a f7 [2] ae f9 [2] 85 d5 [2] ab f7 [2] bf ec [2] b0 f6 [2] ae eb [2] ac ea [2] b7 ec [2] ab eb [2] b7 c4 }

  condition:
    any of them
}