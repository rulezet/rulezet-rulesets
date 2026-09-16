rule TTP_XOR_MULT_DOSStub_ddcb {
  strings:
    $key_ddcb = { 89 a3 [2] fd bb [2] ba b9 [2] fd a8 [2] b3 a4 [2] bf ae [2] a8 a5 [2] b3 eb [2] 8e }

  condition:
    any of them
}