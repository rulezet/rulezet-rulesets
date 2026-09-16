rule TTP_XOR_QUAD_CurrentVersionRun_c5af {
  strings:
    $key_c5af = { 96 c0 [2] b2 ce [2] 99 e2 [2] b7 c0 [2] a3 db [2] ac c1 [2] b2 dc [2] b0 dd [2] ab db [2] b7 dc [2] ab f3 }

  condition:
    any of them
}