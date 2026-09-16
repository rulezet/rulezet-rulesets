rule TTP_XOR_QUAD_CurrentVersionRun_c0af {
  strings:
    $key_c0af = { 93 c0 [2] b7 ce [2] 9c e2 [2] b2 c0 [2] a6 db [2] a9 c1 [2] b7 dc [2] b5 dd [2] ae db [2] b2 dc [2] ae f3 }

  condition:
    any of them
}