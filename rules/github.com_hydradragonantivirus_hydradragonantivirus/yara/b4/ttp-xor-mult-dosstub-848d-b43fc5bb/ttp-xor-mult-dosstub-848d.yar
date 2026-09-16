rule TTP_XOR_MULT_DOSStub_848d {
  strings:
    $key_848d = { d0 e5 [2] a4 fd [2] e3 ff [2] a4 ee [2] ea e2 [2] e6 e8 [2] f1 e3 [2] ea ad [2] d7 }

  condition:
    any of them
}