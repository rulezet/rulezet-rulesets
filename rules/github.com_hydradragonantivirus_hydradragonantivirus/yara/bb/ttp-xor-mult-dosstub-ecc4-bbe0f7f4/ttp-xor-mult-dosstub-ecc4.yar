rule TTP_XOR_MULT_DOSStub_ecc4 {
  strings:
    $key_ecc4 = { b8 ac [2] cc b4 [2] 8b b6 [2] cc a7 [2] 82 ab [2] 8e a1 [2] 99 aa [2] 82 e4 [2] bf }

  condition:
    any of them
}