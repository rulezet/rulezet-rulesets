rule TTP_XOR_MULT_DOSStub_dee2 {
  strings:
    $key_dee2 = { 8a 8a [2] fe 92 [2] b9 90 [2] fe 81 [2] b0 8d [2] bc 87 [2] ab 8c [2] b0 c2 [2] 8d }

  condition:
    any of them
}