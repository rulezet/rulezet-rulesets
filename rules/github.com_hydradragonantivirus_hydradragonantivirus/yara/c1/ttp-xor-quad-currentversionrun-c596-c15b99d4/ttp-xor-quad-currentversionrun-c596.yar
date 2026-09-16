rule TTP_XOR_QUAD_CurrentVersionRun_c596 {
  strings:
    $key_c596 = { 96 f9 [2] b2 f7 [2] 99 db [2] b7 f9 [2] a3 e2 [2] ac f8 [2] b2 e5 [2] b0 e4 [2] ab e2 [2] b7 e5 [2] ab ca }

  condition:
    any of them
}