rule TTP_XOR_QUAD_CurrentVersionRun_cd98 {
  strings:
    $key_cd98 = { 9e f7 [2] ba f9 [2] 91 d5 [2] bf f7 [2] ab ec [2] a4 f6 [2] ba eb [2] b8 ea [2] a3 ec [2] bf eb [2] a3 c4 }

  condition:
    any of them
}