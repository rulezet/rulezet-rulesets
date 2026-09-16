rule TTP_XOR_QUAD_CurrentVersionRun_c584 {
  strings:
    $key_c584 = { 96 eb [2] b2 e5 [2] 99 c9 [2] b7 eb [2] a3 f0 [2] ac ea [2] b2 f7 [2] b0 f6 [2] ab f0 [2] b7 f7 [2] ab d8 }

  condition:
    any of them
}