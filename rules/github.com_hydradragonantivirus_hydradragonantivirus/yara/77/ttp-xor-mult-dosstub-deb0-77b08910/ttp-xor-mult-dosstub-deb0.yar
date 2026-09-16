rule TTP_XOR_MULT_DOSStub_deb0 {
  strings:
    $key_deb0 = { 8a d8 [2] fe c0 [2] b9 c2 [2] fe d3 [2] b0 df [2] bc d5 [2] ab de [2] b0 90 [2] 8d }

  condition:
    any of them
}