rule TTP_XOR_MULT_DOSStub_dee7 {
  strings:
    $key_dee7 = { 8a 8f [2] fe 97 [2] b9 95 [2] fe 84 [2] b0 88 [2] bc 82 [2] ab 89 [2] b0 c7 [2] 8d }

  condition:
    any of them
}