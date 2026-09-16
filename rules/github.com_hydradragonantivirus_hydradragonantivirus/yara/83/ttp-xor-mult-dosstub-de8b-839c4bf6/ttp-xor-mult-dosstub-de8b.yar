rule TTP_XOR_MULT_DOSStub_de8b {
  strings:
    $key_de8b = { 8a e3 [2] fe fb [2] b9 f9 [2] fe e8 [2] b0 e4 [2] bc ee [2] ab e5 [2] b0 ab [2] 8d }

  condition:
    any of them
}