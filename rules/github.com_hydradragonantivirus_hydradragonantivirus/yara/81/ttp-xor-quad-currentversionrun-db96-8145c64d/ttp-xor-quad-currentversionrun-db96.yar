rule TTP_XOR_QUAD_CurrentVersionRun_db96 {
  strings:
    $key_db96 = { 88 f9 [2] ac f7 [2] 87 db [2] a9 f9 [2] bd e2 [2] b2 f8 [2] ac e5 [2] ae e4 [2] b5 e2 [2] a9 e5 [2] b5 ca }

  condition:
    any of them
}