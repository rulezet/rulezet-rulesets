rule TTP_XOR_MULT_DOSStub_ba8e {
  strings:
    $key_ba8e = { ee e6 [2] 9a fe [2] dd fc [2] 9a ed [2] d4 e1 [2] d8 eb [2] cf e0 [2] d4 ae [2] e9 }

  condition:
    any of them
}