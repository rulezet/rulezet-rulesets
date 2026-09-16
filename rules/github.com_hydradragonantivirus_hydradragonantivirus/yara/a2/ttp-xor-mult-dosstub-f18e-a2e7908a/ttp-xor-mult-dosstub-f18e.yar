rule TTP_XOR_MULT_DOSStub_f18e {
  strings:
    $key_f18e = { a5 e6 [2] d1 fe [2] 96 fc [2] d1 ed [2] 9f e1 [2] 93 eb [2] 84 e0 [2] 9f ae [2] a2 }

  condition:
    any of them
}