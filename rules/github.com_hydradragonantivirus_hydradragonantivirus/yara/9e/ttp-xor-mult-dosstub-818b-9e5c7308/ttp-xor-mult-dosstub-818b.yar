rule TTP_XOR_MULT_DOSStub_818b {
  strings:
    $key_818b = { d5 e3 [2] a1 fb [2] e6 f9 [2] a1 e8 [2] ef e4 [2] e3 ee [2] f4 e5 [2] ef ab [2] d2 }

  condition:
    any of them
}