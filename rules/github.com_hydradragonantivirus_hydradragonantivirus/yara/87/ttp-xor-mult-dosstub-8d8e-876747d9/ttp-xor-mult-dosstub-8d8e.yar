rule TTP_XOR_MULT_DOSStub_8d8e {
  strings:
    $key_8d8e = { d9 e6 [2] ad fe [2] ea fc [2] ad ed [2] e3 e1 [2] ef eb [2] f8 e0 [2] e3 ae [2] de }

  condition:
    any of them
}