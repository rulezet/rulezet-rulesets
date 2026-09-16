rule TTP_XOR_MULT_DOSStub_ddc2 {
  strings:
    $key_ddc2 = { 89 aa [2] fd b2 [2] ba b0 [2] fd a1 [2] b3 ad [2] bf a7 [2] a8 ac [2] b3 e2 [2] 8e }

  condition:
    any of them
}