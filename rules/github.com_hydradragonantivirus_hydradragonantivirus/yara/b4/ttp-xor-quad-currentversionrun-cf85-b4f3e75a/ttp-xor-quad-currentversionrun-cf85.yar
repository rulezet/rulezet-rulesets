rule TTP_XOR_QUAD_CurrentVersionRun_cf85 {
  strings:
    $key_cf85 = { 9c ea [2] b8 e4 [2] 93 c8 [2] bd ea [2] a9 f1 [2] a6 eb [2] b8 f6 [2] ba f7 [2] a1 f1 [2] bd f6 [2] a1 d9 }

  condition:
    any of them
}