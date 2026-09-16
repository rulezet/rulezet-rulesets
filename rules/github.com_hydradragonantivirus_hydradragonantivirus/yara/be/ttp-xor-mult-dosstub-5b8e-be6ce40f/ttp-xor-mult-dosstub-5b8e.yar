rule TTP_XOR_MULT_DOSStub_5b8e {
  strings:
    $key_5b8e = { 0f e6 [2] 7b fe [2] 3c fc [2] 7b ed [2] 35 e1 [2] 39 eb [2] 2e e0 [2] 35 ae [2] 08 }

  condition:
    any of them
}