rule TTP_XOR_MULT_DOSStub_ecc6 {
  strings:
    $key_ecc6 = { b8 ae [2] cc b6 [2] 8b b4 [2] cc a5 [2] 82 a9 [2] 8e a3 [2] 99 a8 [2] 82 e6 [2] bf }

  condition:
    any of them
}