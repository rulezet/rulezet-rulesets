rule TTP_XOR_MULT_DOSStub_de9e {
  strings:
    $key_de9e = { 8a f6 [2] fe ee [2] b9 ec [2] fe fd [2] b0 f1 [2] bc fb [2] ab f0 [2] b0 be [2] 8d }

  condition:
    any of them
}