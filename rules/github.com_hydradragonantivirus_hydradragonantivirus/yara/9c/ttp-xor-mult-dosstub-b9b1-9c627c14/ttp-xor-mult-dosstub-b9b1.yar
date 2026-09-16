rule TTP_XOR_MULT_DOSStub_b9b1 {
  strings:
    $key_b9b1 = { ed d9 [2] 99 c1 [2] de c3 [2] 99 d2 [2] d7 de [2] db d4 [2] cc df [2] d7 91 [2] ea }

  condition:
    any of them
}