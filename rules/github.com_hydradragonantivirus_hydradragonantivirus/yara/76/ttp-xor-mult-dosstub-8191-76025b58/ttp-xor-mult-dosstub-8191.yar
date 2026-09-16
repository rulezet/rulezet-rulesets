rule TTP_XOR_MULT_DOSStub_8191 {
  strings:
    $key_8191 = { d5 f9 [2] a1 e1 [2] e6 e3 [2] a1 f2 [2] ef fe [2] e3 f4 [2] f4 ff [2] ef b1 [2] d2 }

  condition:
    any of them
}