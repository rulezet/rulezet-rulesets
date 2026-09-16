rule TTP_XOR_MULT_DOSStub_728e {
  strings:
    $key_728e = { 26 e6 [2] 52 fe [2] 15 fc [2] 52 ed [2] 1c e1 [2] 10 eb [2] 07 e0 [2] 1c ae [2] 21 }

  condition:
    any of them
}