rule TTP_XOR_QUAD_CurrentVersionRun_db86 {
  strings:
    $key_db86 = { 88 e9 [2] ac e7 [2] 87 cb [2] a9 e9 [2] bd f2 [2] b2 e8 [2] ac f5 [2] ae f4 [2] b5 f2 [2] a9 f5 [2] b5 da }

  condition:
    any of them
}