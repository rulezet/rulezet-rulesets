rule TTP_XOR_MULT_DOSStub_328c {
  strings:
    $key_328c = { 66 e4 [2] 12 fc [2] 55 fe [2] 12 ef [2] 5c e3 [2] 50 e9 [2] 47 e2 [2] 5c ac [2] 61 }

  condition:
    any of them
}