rule TTP_XOR_MULT_DOSStub_708e {
  strings:
    $key_708e = { 24 e6 [2] 50 fe [2] 17 fc [2] 50 ed [2] 1e e1 [2] 12 eb [2] 05 e0 [2] 1e ae [2] 23 }

  condition:
    any of them
}