rule TTP_XOR_MULT_DOSStub_acb0 {
  strings:
    $key_acb0 = { f8 d8 [2] 8c c0 [2] cb c2 [2] 8c d3 [2] c2 df [2] ce d5 [2] d9 de [2] c2 90 [2] ff }

  condition:
    any of them
}