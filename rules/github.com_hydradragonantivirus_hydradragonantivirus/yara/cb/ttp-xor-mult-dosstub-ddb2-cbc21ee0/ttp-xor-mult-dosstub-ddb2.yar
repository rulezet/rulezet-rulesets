rule TTP_XOR_MULT_DOSStub_ddb2 {
  strings:
    $key_ddb2 = { 89 da [2] fd c2 [2] ba c0 [2] fd d1 [2] b3 dd [2] bf d7 [2] a8 dc [2] b3 92 [2] 8e }

  condition:
    any of them
}