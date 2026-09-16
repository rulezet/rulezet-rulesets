rule TTP_XOR_MULT_DOSStub_ddd2 {
  strings:
    $key_ddd2 = { 89 ba [2] fd a2 [2] ba a0 [2] fd b1 [2] b3 bd [2] bf b7 [2] a8 bc [2] b3 f2 [2] 8e }

  condition:
    any of them
}