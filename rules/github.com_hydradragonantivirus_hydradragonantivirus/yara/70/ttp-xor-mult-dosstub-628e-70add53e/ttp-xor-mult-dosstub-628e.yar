rule TTP_XOR_MULT_DOSStub_628e {
  strings:
    $key_628e = { 36 e6 [2] 42 fe [2] 05 fc [2] 42 ed [2] 0c e1 [2] 00 eb [2] 17 e0 [2] 0c ae [2] 31 }

  condition:
    any of them
}