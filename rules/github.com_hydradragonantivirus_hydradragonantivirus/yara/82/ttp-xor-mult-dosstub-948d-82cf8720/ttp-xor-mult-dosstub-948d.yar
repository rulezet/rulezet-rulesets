rule TTP_XOR_MULT_DOSStub_948d {
  strings:
    $key_948d = { c0 e5 [2] b4 fd [2] f3 ff [2] b4 ee [2] fa e2 [2] f6 e8 [2] e1 e3 [2] fa ad [2] c7 }

  condition:
    any of them
}