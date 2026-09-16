rule TTP_XOR_MULT_DOSStub_708c {
  strings:
    $key_708c = { 24 e4 [2] 50 fc [2] 17 fe [2] 50 ef [2] 1e e3 [2] 12 e9 [2] 05 e2 [2] 1e ac [2] 23 }

  condition:
    any of them
}