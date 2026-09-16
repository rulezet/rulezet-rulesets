rule TTP_XOR_QUAD_CurrentVersionRun_98bf {
  strings:
    $key_98bf = { cb d0 [2] ef de [2] c4 f2 [2] ea d0 [2] fe cb [2] f1 d1 [2] ef cc [2] ed cd [2] f6 cb [2] ea cc [2] f6 e3 }

  condition:
    any of them
}