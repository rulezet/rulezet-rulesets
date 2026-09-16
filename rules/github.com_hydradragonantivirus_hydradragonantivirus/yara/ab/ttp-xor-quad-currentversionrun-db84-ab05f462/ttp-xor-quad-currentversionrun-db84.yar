rule TTP_XOR_QUAD_CurrentVersionRun_db84 {
  strings:
    $key_db84 = { 88 eb [2] ac e5 [2] 87 c9 [2] a9 eb [2] bd f0 [2] b2 ea [2] ac f7 [2] ae f6 [2] b5 f0 [2] a9 f7 [2] b5 d8 }

  condition:
    any of them
}