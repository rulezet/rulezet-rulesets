rule TTP_XOR_MULT_DOSStub_408e {
  strings:
    $key_408e = { 14 e6 [2] 60 fe [2] 27 fc [2] 60 ed [2] 2e e1 [2] 22 eb [2] 35 e0 [2] 2e ae [2] 13 }

  condition:
    any of them
}