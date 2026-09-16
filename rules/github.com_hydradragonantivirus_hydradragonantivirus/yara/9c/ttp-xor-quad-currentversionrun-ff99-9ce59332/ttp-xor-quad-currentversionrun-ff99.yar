rule TTP_XOR_QUAD_CurrentVersionRun_ff99 {
  strings:
    $key_ff99 = { ac f6 [2] 88 f8 [2] a3 d4 [2] 8d f6 [2] 99 ed [2] 96 f7 [2] 88 ea [2] 8a eb [2] 91 ed [2] 8d ea [2] 91 c5 }

  condition:
    any of them
}