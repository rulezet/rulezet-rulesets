rule TTP_XOR_MULT_DOSStub_8b8c {
  strings:
    $key_8b8c = { df e4 [2] ab fc [2] ec fe [2] ab ef [2] e5 e3 [2] e9 e9 [2] fe e2 [2] e5 ac [2] d8 }

  condition:
    any of them
}