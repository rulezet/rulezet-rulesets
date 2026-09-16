rule TTP_XOR_MULT_DOSStub_ddc1 {
  strings:
    $key_ddc1 = { 89 a9 [2] fd b1 [2] ba b3 [2] fd a2 [2] b3 ae [2] bf a4 [2] a8 af [2] b3 e1 [2] 8e }

  condition:
    any of them
}