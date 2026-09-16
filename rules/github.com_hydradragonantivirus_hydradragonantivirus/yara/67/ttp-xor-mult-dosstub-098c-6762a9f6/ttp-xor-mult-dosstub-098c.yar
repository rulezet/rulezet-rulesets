rule TTP_XOR_MULT_DOSStub_098c {
  strings:
    $key_098c = { 5d e4 [2] 29 fc [2] 6e fe [2] 29 ef [2] 67 e3 [2] 6b e9 [2] 7c e2 [2] 67 ac [2] 5a }

  condition:
    any of them
}