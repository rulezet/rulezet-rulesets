rule TTP_XOR_QUAD_CurrentVersionRun_a2af {
  strings:
    $key_a2af = { f1 c0 [2] d5 ce [2] fe e2 [2] d0 c0 [2] c4 db [2] cb c1 [2] d5 dc [2] d7 dd [2] cc db [2] d0 dc [2] cc f3 }

  condition:
    any of them
}