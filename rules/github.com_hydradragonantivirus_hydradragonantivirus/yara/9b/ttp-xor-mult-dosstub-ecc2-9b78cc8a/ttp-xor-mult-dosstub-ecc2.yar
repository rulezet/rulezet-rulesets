rule TTP_XOR_MULT_DOSStub_ecc2 {
  strings:
    $key_ecc2 = { b8 aa [2] cc b2 [2] 8b b0 [2] cc a1 [2] 82 ad [2] 8e a7 [2] 99 ac [2] 82 e2 [2] bf }

  condition:
    any of them
}