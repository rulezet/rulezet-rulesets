rule TTP_XOR_MULT_DOSStub_ddc7 {
  strings:
    $key_ddc7 = { 89 af [2] fd b7 [2] ba b5 [2] fd a4 [2] b3 a8 [2] bf a2 [2] a8 a9 [2] b3 e7 [2] 8e }

  condition:
    any of them
}