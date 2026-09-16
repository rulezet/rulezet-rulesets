rule TTP_XOR_QUAD_CurrentVersionRun_db85 {
  strings:
    $key_db85 = { 88 ea [2] ac e4 [2] 87 c8 [2] a9 ea [2] bd f1 [2] b2 eb [2] ac f6 [2] ae f7 [2] b5 f1 [2] a9 f6 [2] b5 d9 }

  condition:
    any of them
}