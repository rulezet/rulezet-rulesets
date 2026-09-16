rule TTP_XOR_QUAD_CurrentVersionRun_d2af {
  strings:
    $key_d2af = { 81 c0 [2] a5 ce [2] 8e e2 [2] a0 c0 [2] b4 db [2] bb c1 [2] a5 dc [2] a7 dd [2] bc db [2] a0 dc [2] bc f3 }

  condition:
    any of them
}