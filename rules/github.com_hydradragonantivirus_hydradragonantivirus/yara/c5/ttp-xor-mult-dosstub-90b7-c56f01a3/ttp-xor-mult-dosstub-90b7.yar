rule TTP_XOR_MULT_DOSStub_90b7 {
  strings:
    $key_90b7 = { c4 df [2] b0 c7 [2] f7 c5 [2] b0 d4 [2] fe d8 [2] f2 d2 [2] e5 d9 [2] fe 97 [2] c3 }

  condition:
    any of them
}