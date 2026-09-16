rule TTP_XOR_MULT_DOSStub_f7c2 {
  strings:
    $key_f7c2 = { a3 aa [2] d7 b2 [2] 90 b0 [2] d7 a1 [2] 99 ad [2] 95 a7 [2] 82 ac [2] 99 e2 [2] a4 }

  condition:
    any of them
}