rule TTP_XOR_MULT_DOSStub_f4c2 {
  strings:
    $key_f4c2 = { a0 aa [2] d4 b2 [2] 93 b0 [2] d4 a1 [2] 9a ad [2] 96 a7 [2] 81 ac [2] 9a e2 [2] a7 }

  condition:
    any of them
}