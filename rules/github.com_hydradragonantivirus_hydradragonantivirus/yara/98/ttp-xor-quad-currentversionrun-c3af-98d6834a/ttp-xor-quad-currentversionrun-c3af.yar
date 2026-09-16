rule TTP_XOR_QUAD_CurrentVersionRun_c3af {
  strings:
    $key_c3af = { 90 c0 [2] b4 ce [2] 9f e2 [2] b1 c0 [2] a5 db [2] aa c1 [2] b4 dc [2] b6 dd [2] ad db [2] b1 dc [2] ad f3 }

  condition:
    any of them
}