rule TTP_XOR_MULT_DOSStub_f0c2 {
  strings:
    $key_f0c2 = { a4 aa [2] d0 b2 [2] 97 b0 [2] d0 a1 [2] 9e ad [2] 92 a7 [2] 85 ac [2] 9e e2 [2] a3 }

  condition:
    any of them
}