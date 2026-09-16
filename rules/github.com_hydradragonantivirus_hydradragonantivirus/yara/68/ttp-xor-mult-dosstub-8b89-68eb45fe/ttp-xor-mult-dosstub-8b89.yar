rule TTP_XOR_MULT_DOSStub_8b89 {
  strings:
    $key_8b89 = { df e1 [2] ab f9 [2] ec fb [2] ab ea [2] e5 e6 [2] e9 ec [2] fe e7 [2] e5 a9 [2] d8 }

  condition:
    any of them
}