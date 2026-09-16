rule TTP_XOR_MULT_DOSStub_778e {
  strings:
    $key_778e = { 23 e6 [2] 57 fe [2] 10 fc [2] 57 ed [2] 19 e1 [2] 15 eb [2] 02 e0 [2] 19 ae [2] 24 }

  condition:
    any of them
}