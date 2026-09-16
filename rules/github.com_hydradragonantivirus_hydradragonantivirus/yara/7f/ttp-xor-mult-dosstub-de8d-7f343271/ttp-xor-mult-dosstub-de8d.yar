rule TTP_XOR_MULT_DOSStub_de8d {
  strings:
    $key_de8d = { 8a e5 [2] fe fd [2] b9 ff [2] fe ee [2] b0 e2 [2] bc e8 [2] ab e3 [2] b0 ad [2] 8d }

  condition:
    any of them
}