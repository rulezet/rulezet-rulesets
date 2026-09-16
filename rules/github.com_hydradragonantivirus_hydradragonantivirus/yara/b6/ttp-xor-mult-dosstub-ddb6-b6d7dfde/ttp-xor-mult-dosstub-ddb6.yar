rule TTP_XOR_MULT_DOSStub_ddb6 {
  strings:
    $key_ddb6 = { 89 de [2] fd c6 [2] ba c4 [2] fd d5 [2] b3 d9 [2] bf d3 [2] a8 d8 [2] b3 96 [2] 8e }

  condition:
    any of them
}