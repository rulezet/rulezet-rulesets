rule TTP_XOR_MULT_DOSStub_1b8e {
  strings:
    $key_1b8e = { 4f e6 [2] 3b fe [2] 7c fc [2] 3b ed [2] 75 e1 [2] 79 eb [2] 6e e0 [2] 75 ae [2] 48 }

  condition:
    any of them
}