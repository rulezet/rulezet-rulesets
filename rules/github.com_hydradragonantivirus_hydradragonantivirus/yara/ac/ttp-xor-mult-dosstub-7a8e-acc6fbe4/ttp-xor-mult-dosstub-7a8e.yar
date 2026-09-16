rule TTP_XOR_MULT_DOSStub_7a8e {
  strings:
    $key_7a8e = { 2e e6 [2] 5a fe [2] 1d fc [2] 5a ed [2] 14 e1 [2] 18 eb [2] 0f e0 [2] 14 ae [2] 29 }

  condition:
    any of them
}