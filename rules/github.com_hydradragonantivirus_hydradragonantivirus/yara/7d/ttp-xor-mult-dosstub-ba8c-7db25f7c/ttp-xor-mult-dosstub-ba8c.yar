rule TTP_XOR_MULT_DOSStub_ba8c {
  strings:
    $key_ba8c = { ee e4 [2] 9a fc [2] dd fe [2] 9a ef [2] d4 e3 [2] d8 e9 [2] cf e2 [2] d4 ac [2] e9 }

  condition:
    any of them
}