rule TTP_XOR_MULT_DOSStub_81be {
  strings:
    $key_81be = { d5 d6 [2] a1 ce [2] e6 cc [2] a1 dd [2] ef d1 [2] e3 db [2] f4 d0 [2] ef 9e [2] d2 }

  condition:
    any of them
}