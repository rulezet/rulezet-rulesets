rule TTP_XOR_QUAD_CurrentVersionRun_d7af {
  strings:
    $key_d7af = { 84 c0 [2] a0 ce [2] 8b e2 [2] a5 c0 [2] b1 db [2] be c1 [2] a0 dc [2] a2 dd [2] b9 db [2] a5 dc [2] b9 f3 }

  condition:
    any of them
}