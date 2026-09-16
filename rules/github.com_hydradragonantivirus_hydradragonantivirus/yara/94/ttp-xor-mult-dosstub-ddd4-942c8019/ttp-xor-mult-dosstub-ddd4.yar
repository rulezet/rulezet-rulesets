rule TTP_XOR_MULT_DOSStub_ddd4 {
  strings:
    $key_ddd4 = { 89 bc [2] fd a4 [2] ba a6 [2] fd b7 [2] b3 bb [2] bf b1 [2] a8 ba [2] b3 f4 [2] 8e }

  condition:
    any of them
}