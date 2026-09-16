rule TTP_XOR_QUAD_CurrentVersionRun_84ba {
  strings:
    $key_84ba = { d7 d5 [2] f3 db [2] d8 f7 [2] f6 d5 [2] e2 ce [2] ed d4 [2] f3 c9 [2] f1 c8 [2] ea ce [2] f6 c9 [2] ea e6 }

  condition:
    any of them
}