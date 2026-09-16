rule TTP_XOR_MULT_DOSStub_788c {
  strings:
    $key_788c = { 2c e4 [2] 58 fc [2] 1f fe [2] 58 ef [2] 16 e3 [2] 1a e9 [2] 0d e2 [2] 16 ac [2] 2b }

  condition:
    any of them
}