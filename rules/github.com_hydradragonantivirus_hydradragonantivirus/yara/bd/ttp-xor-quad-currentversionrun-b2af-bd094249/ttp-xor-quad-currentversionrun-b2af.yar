rule TTP_XOR_QUAD_CurrentVersionRun_b2af {
  strings:
    $key_b2af = { e1 c0 [2] c5 ce [2] ee e2 [2] c0 c0 [2] d4 db [2] db c1 [2] c5 dc [2] c7 dd [2] dc db [2] c0 dc [2] dc f3 }

  condition:
    any of them
}