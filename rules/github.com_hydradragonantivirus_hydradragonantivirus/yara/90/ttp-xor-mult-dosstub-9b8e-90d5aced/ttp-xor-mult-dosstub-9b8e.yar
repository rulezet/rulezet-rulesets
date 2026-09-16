rule TTP_XOR_MULT_DOSStub_9b8e {
  strings:
    $key_9b8e = { cf e6 [2] bb fe [2] fc fc [2] bb ed [2] f5 e1 [2] f9 eb [2] ee e0 [2] f5 ae [2] c8 }

  condition:
    any of them
}