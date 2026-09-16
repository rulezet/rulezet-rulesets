rule TTP_XOR_MULT_DOSStub_90e7 {
  strings:
    $key_90e7 = { c4 8f [2] b0 97 [2] f7 95 [2] b0 84 [2] fe 88 [2] f2 82 [2] e5 89 [2] fe c7 [2] c3 }

  condition:
    any of them
}