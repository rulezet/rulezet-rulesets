rule TTP_XOR_MULT_DOSStub_d39c {
  strings:
    $key_d39c = { 87 f4 [2] f3 ec [2] b4 ee [2] f3 ff [2] bd f3 [2] b1 f9 [2] a6 f2 [2] bd bc [2] 80 }

  condition:
    any of them
}