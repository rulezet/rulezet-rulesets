rule TTP_XOR_MULT_DOSStub_888c {
  strings:
    $key_888c = { dc e4 [2] a8 fc [2] ef fe [2] a8 ef [2] e6 e3 [2] ea e9 [2] fd e2 [2] e6 ac [2] db }

  condition:
    any of them
}