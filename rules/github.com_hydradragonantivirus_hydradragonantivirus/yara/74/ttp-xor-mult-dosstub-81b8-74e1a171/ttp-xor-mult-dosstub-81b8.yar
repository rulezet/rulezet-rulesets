rule TTP_XOR_MULT_DOSStub_81b8 {
  strings:
    $key_81b8 = { d5 d0 [2] a1 c8 [2] e6 ca [2] a1 db [2] ef d7 [2] e3 dd [2] f4 d6 [2] ef 98 [2] d2 }

  condition:
    any of them
}