rule TTP_XOR_QUAD_CurrentVersionRun_98ba {
  strings:
    $key_98ba = { cb d5 [2] ef db [2] c4 f7 [2] ea d5 [2] fe ce [2] f1 d4 [2] ef c9 [2] ed c8 [2] f6 ce [2] ea c9 [2] f6 e6 }

  condition:
    any of them
}