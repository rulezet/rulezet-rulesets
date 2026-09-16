rule TTP_XOR_MULT_DOSStub_def8 {
  strings:
    $key_def8 = { 8a 90 [2] fe 88 [2] b9 8a [2] fe 9b [2] b0 97 [2] bc 9d [2] ab 96 [2] b0 d8 [2] 8d }

  condition:
    any of them
}