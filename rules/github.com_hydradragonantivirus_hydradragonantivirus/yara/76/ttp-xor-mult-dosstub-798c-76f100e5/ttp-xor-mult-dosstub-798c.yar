rule TTP_XOR_MULT_DOSStub_798c {
  strings:
    $key_798c = { 2d e4 [2] 59 fc [2] 1e fe [2] 59 ef [2] 17 e3 [2] 1b e9 [2] 0c e2 [2] 17 ac [2] 2a }

  condition:
    any of them
}