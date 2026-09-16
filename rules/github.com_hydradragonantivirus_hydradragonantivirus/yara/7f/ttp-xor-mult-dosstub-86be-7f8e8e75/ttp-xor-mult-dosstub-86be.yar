rule TTP_XOR_MULT_DOSStub_86be {
  strings:
    $key_86be = { d2 d6 [2] a6 ce [2] e1 cc [2] a6 dd [2] e8 d1 [2] e4 db [2] f3 d0 [2] e8 9e [2] d5 }

  condition:
    any of them
}