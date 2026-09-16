rule TTP_XOR_QUAD_CurrentVersionRun_26af {
  strings:
    $key_26af = { 75 c0 [2] 51 ce [2] 7a e2 [2] 54 c0 [2] 40 db [2] 4f c1 [2] 51 dc [2] 53 dd [2] 48 db [2] 54 dc [2] 48 f3 }

  condition:
    any of them
}