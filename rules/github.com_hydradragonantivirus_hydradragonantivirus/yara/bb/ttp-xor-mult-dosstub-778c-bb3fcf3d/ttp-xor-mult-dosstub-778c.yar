rule TTP_XOR_MULT_DOSStub_778c {
  strings:
    $key_778c = { 23 e4 [2] 57 fc [2] 10 fe [2] 57 ef [2] 19 e3 [2] 15 e9 [2] 02 e2 [2] 19 ac [2] 24 }

  condition:
    any of them
}