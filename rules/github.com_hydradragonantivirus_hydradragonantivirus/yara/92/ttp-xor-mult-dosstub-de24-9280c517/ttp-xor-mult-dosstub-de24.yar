rule TTP_XOR_MULT_DOSStub_de24 {
  strings:
    $key_de24 = { 8a 4c [2] fe 54 [2] b9 56 [2] fe 47 [2] b0 4b [2] bc 41 [2] ab 4a [2] b0 04 [2] 8d }

  condition:
    any of them
}