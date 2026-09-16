rule TTP_XOR_MULT_DOSStub_d38d {
  strings:
    $key_d38d = { 87 e5 [2] f3 fd [2] b4 ff [2] f3 ee [2] bd e2 [2] b1 e8 [2] a6 e3 [2] bd ad [2] 80 }

  condition:
    any of them
}