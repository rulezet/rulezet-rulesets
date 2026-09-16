rule TTP_XOR_MULT_DOSStub_84df {
  strings:
    $key_84df = { d0 b7 [2] a4 af [2] e3 ad [2] a4 bc [2] ea b0 [2] e6 ba [2] f1 b1 [2] ea ff [2] d7 }

  condition:
    any of them
}