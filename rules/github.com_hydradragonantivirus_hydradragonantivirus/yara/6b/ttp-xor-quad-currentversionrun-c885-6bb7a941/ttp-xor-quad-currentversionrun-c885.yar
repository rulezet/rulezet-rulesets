rule TTP_XOR_QUAD_CurrentVersionRun_c885 {
  strings:
    $key_c885 = { 9b ea [2] bf e4 [2] 94 c8 [2] ba ea [2] ae f1 [2] a1 eb [2] bf f6 [2] bd f7 [2] a6 f1 [2] ba f6 [2] a6 d9 }

  condition:
    any of them
}