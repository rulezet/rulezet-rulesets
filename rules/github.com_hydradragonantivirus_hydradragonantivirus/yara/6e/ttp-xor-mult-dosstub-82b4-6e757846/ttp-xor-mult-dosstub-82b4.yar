rule TTP_XOR_MULT_DOSStub_82b4 {
  strings:
    $key_82b4 = { d6 dc [2] a2 c4 [2] e5 c6 [2] a2 d7 [2] ec db [2] e0 d1 [2] f7 da [2] ec 94 [2] d1 }

  condition:
    any of them
}