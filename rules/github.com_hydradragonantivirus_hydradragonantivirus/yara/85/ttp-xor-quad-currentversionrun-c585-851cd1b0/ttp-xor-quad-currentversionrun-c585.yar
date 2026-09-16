rule TTP_XOR_QUAD_CurrentVersionRun_c585 {
  strings:
    $key_c585 = { 96 ea [2] b2 e4 [2] 99 c8 [2] b7 ea [2] a3 f1 [2] ac eb [2] b2 f6 [2] b0 f7 [2] ab f1 [2] b7 f6 [2] ab d9 }

  condition:
    any of them
}