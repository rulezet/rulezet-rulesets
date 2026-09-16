rule TTP_XOR_QUAD_CurrentVersionRun_d4ba {
  strings:
    $key_d4ba = { 87 d5 [2] a3 db [2] 88 f7 [2] a6 d5 [2] b2 ce [2] bd d4 [2] a3 c9 [2] a1 c8 [2] ba ce [2] a6 c9 [2] ba e6 }

  condition:
    any of them
}