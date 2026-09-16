rule TTP_XOR_MULT_DOSStub_81ad {
  strings:
    $key_81ad = { d5 c5 [2] a1 dd [2] e6 df [2] a1 ce [2] ef c2 [2] e3 c8 [2] f4 c3 [2] ef 8d [2] d2 }

  condition:
    any of them
}