rule TTP_XOR_MULT_DOSStub_de8e {
  strings:
    $key_de8e = { 8a e6 [2] fe fe [2] b9 fc [2] fe ed [2] b0 e1 [2] bc eb [2] ab e0 [2] b0 ae [2] 8d }

  condition:
    any of them
}