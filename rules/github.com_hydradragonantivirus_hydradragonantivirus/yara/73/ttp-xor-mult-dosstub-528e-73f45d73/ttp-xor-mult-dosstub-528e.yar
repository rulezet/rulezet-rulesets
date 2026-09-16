rule TTP_XOR_MULT_DOSStub_528e {
  strings:
    $key_528e = { 06 e6 [2] 72 fe [2] 35 fc [2] 72 ed [2] 3c e1 [2] 30 eb [2] 27 e0 [2] 3c ae [2] 01 }

  condition:
    any of them
}