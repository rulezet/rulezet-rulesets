rule TTP_XOR_QUAD_CurrentVersionRun_ceba {
  strings:
    $key_ceba = { 9d d5 [2] b9 db [2] 92 f7 [2] bc d5 [2] a8 ce [2] a7 d4 [2] b9 c9 [2] bb c8 [2] a0 ce [2] bc c9 [2] a0 e6 }

  condition:
    any of them
}