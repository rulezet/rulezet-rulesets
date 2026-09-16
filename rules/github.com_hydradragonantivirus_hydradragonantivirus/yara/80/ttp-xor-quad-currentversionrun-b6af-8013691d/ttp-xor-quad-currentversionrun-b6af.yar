rule TTP_XOR_QUAD_CurrentVersionRun_b6af {
  strings:
    $key_b6af = { e5 c0 [2] c1 ce [2] ea e2 [2] c4 c0 [2] d0 db [2] df c1 [2] c1 dc [2] c3 dd [2] d8 db [2] c4 dc [2] d8 f3 }

  condition:
    any of them
}