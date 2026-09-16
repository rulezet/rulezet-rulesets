rule TTP_XOR_QUAD_CurrentVersionRun_de99 {
  strings:
    $key_de99 = { 8d f6 [2] a9 f8 [2] 82 d4 [2] ac f6 [2] b8 ed [2] b7 f7 [2] a9 ea [2] ab eb [2] b0 ed [2] ac ea [2] b0 c5 }

  condition:
    any of them
}