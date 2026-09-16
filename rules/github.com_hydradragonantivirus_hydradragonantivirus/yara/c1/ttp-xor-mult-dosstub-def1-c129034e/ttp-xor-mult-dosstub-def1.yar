rule TTP_XOR_MULT_DOSStub_def1 {
  strings:
    $key_def1 = { 8a 99 [2] fe 81 [2] b9 83 [2] fe 92 [2] b0 9e [2] bc 94 [2] ab 9f [2] b0 d1 [2] 8d }

  condition:
    any of them
}