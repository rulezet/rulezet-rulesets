rule TTP_XOR_MULT_DOSStub_918d {
  strings:
    $key_918d = { c5 e5 [2] b1 fd [2] f6 ff [2] b1 ee [2] ff e2 [2] f3 e8 [2] e4 e3 [2] ff ad [2] c2 }

  condition:
    any of them
}