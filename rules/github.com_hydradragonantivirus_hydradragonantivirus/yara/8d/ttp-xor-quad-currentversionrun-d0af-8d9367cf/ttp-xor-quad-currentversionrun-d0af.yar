rule TTP_XOR_QUAD_CurrentVersionRun_d0af {
  strings:
    $key_d0af = { 83 c0 [2] a7 ce [2] 8c e2 [2] a2 c0 [2] b6 db [2] b9 c1 [2] a7 dc [2] a5 dd [2] be db [2] a2 dc [2] be f3 }

  condition:
    any of them
}