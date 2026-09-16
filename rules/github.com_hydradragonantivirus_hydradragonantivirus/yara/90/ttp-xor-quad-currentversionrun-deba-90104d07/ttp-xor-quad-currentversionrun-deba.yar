rule TTP_XOR_QUAD_CurrentVersionRun_deba {
  strings:
    $key_deba = { 8d d5 [2] a9 db [2] 82 f7 [2] ac d5 [2] b8 ce [2] b7 d4 [2] a9 c9 [2] ab c8 [2] b0 ce [2] ac c9 [2] b0 e6 }

  condition:
    any of them
}