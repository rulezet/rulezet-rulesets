rule TTP_XOR_MULT_DOSStub_8197 {
  strings:
    $key_8197 = { d5 ff [2] a1 e7 [2] e6 e5 [2] a1 f4 [2] ef f8 [2] e3 f2 [2] f4 f9 [2] ef b7 [2] d2 }

  condition:
    any of them
}