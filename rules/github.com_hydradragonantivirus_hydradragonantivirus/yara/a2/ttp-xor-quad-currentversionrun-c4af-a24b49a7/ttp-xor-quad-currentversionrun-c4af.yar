rule TTP_XOR_QUAD_CurrentVersionRun_c4af {
  strings:
    $key_c4af = { 97 c0 [2] b3 ce [2] 98 e2 [2] b6 c0 [2] a2 db [2] ad c1 [2] b3 dc [2] b1 dd [2] aa db [2] b6 dc [2] aa f3 }

  condition:
    any of them
}