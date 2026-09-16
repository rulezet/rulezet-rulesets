rule TTP_XOR_QUAD_CurrentVersionRun_94af {
  strings:
    $key_94af = { c7 c0 [2] e3 ce [2] c8 e2 [2] e6 c0 [2] f2 db [2] fd c1 [2] e3 dc [2] e1 dd [2] fa db [2] e6 dc [2] fa f3 }

  condition:
    any of them
}