rule TTP_XOR_MULT_DOSStub_ddd6 {
  strings:
    $key_ddd6 = { 89 be [2] fd a6 [2] ba a4 [2] fd b5 [2] b3 b9 [2] bf b3 [2] a8 b8 [2] b3 f6 [2] 8e }

  condition:
    any of them
}