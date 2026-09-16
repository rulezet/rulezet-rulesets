rule TTP_XOR_QUAD_CurrentVersionRun_c6af {
  strings:
    $key_c6af = { 95 c0 [2] b1 ce [2] 9a e2 [2] b4 c0 [2] a0 db [2] af c1 [2] b1 dc [2] b3 dd [2] a8 db [2] b4 dc [2] a8 f3 }

  condition:
    any of them
}