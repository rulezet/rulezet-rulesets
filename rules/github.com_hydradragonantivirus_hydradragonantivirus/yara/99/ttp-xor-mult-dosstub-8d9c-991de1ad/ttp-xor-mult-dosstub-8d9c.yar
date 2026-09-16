rule TTP_XOR_MULT_DOSStub_8d9c {
  strings:
    $key_8d9c = { d9 f4 [2] ad ec [2] ea ee [2] ad ff [2] e3 f3 [2] ef f9 [2] f8 f2 [2] e3 bc [2] de }

  condition:
    any of them
}