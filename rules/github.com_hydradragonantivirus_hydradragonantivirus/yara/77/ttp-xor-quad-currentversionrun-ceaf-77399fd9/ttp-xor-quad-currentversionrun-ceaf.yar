rule TTP_XOR_QUAD_CurrentVersionRun_ceaf {
  strings:
    $key_ceaf = { 9d c0 [2] b9 ce [2] 92 e2 [2] bc c0 [2] a8 db [2] a7 c1 [2] b9 dc [2] bb dd [2] a0 db [2] bc dc [2] a0 f3 }

  condition:
    any of them
}