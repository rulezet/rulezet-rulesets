rule TTP_XOR_MULT_DOSStub_90e5 {
  strings:
    $key_90e5 = { c4 8d [2] b0 95 [2] f7 97 [2] b0 86 [2] fe 8a [2] f2 80 [2] e5 8b [2] fe c5 [2] c3 }

  condition:
    any of them
}