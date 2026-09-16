rule TTP_XOR_MULT_DOSStub_ddc6 {
  strings:
    $key_ddc6 = { 89 ae [2] fd b6 [2] ba b4 [2] fd a5 [2] b3 a9 [2] bf a3 [2] a8 a8 [2] b3 e6 [2] 8e }

  condition:
    any of them
}