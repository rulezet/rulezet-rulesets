rule TTP_XOR_MULT_DOSStub_908d {
  strings:
    $key_908d = { c4 e5 [2] b0 fd [2] f7 ff [2] b0 ee [2] fe e2 [2] f2 e8 [2] e5 e3 [2] fe ad [2] c3 }

  condition:
    any of them
}