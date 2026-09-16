rule TTP_XOR_MULT_DOSStub_968d {
  strings:
    $key_968d = { c2 e5 [2] b6 fd [2] f1 ff [2] b6 ee [2] f8 e2 [2] f4 e8 [2] e3 e3 [2] f8 ad [2] c5 }

  condition:
    any of them
}