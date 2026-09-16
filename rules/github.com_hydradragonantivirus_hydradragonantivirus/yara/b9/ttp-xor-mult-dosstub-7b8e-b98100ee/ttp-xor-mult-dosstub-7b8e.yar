rule TTP_XOR_MULT_DOSStub_7b8e {
  strings:
    $key_7b8e = { 2f e6 [2] 5b fe [2] 1c fc [2] 5b ed [2] 15 e1 [2] 19 eb [2] 0e e0 [2] 15 ae [2] 28 }

  condition:
    any of them
}