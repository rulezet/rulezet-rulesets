rule TTP_XOR_MULT_DOSStub_ecc5 {
  strings:
    $key_ecc5 = { b8 ad [2] cc b5 [2] 8b b7 [2] cc a6 [2] 82 aa [2] 8e a0 [2] 99 ab [2] 82 e5 [2] bf }

  condition:
    any of them
}