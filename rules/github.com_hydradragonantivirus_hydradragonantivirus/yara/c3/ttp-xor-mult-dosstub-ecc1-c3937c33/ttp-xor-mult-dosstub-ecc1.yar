rule TTP_XOR_MULT_DOSStub_ecc1 {
  strings:
    $key_ecc1 = { b8 a9 [2] cc b1 [2] 8b b3 [2] cc a2 [2] 82 ae [2] 8e a4 [2] 99 af [2] 82 e1 [2] bf }

  condition:
    any of them
}