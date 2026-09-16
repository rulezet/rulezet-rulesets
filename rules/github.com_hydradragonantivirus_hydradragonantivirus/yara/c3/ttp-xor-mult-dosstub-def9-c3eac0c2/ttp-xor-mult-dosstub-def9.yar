rule TTP_XOR_MULT_DOSStub_def9 {
  strings:
    $key_def9 = { 8a 91 [2] fe 89 [2] b9 8b [2] fe 9a [2] b0 96 [2] bc 9c [2] ab 97 [2] b0 d9 [2] 8d }

  condition:
    any of them
}