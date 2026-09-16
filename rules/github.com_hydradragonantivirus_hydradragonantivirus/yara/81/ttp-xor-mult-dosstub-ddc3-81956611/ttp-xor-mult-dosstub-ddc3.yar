rule TTP_XOR_MULT_DOSStub_ddc3 {
  strings:
    $key_ddc3 = { 89 ab [2] fd b3 [2] ba b1 [2] fd a0 [2] b3 ac [2] bf a6 [2] a8 ad [2] b3 e3 [2] 8e }

  condition:
    any of them
}