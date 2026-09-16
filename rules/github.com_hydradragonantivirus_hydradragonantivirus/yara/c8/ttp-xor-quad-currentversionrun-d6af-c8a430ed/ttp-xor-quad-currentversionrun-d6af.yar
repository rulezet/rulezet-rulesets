rule TTP_XOR_QUAD_CurrentVersionRun_d6af {
  strings:
    $key_d6af = { 85 c0 [2] a1 ce [2] 8a e2 [2] a4 c0 [2] b0 db [2] bf c1 [2] a1 dc [2] a3 dd [2] b8 db [2] a4 dc [2] b8 f3 }

  condition:
    any of them
}