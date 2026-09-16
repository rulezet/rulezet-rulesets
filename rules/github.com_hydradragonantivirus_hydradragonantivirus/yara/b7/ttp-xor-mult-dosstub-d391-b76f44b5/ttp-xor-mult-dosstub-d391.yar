rule TTP_XOR_MULT_DOSStub_d391 {
  strings:
    $key_d391 = { 87 f9 [2] f3 e1 [2] b4 e3 [2] f3 f2 [2] bd fe [2] b1 f4 [2] a6 ff [2] bd b1 [2] 80 }

  condition:
    any of them
}