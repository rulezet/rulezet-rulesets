rule TTP_XOR_QUAD_CurrentVersionRun_d5af {
  strings:
    $key_d5af = { 86 c0 [2] a2 ce [2] 89 e2 [2] a7 c0 [2] b3 db [2] bc c1 [2] a2 dc [2] a0 dd [2] bb db [2] a7 dc [2] bb f3 }

  condition:
    any of them
}