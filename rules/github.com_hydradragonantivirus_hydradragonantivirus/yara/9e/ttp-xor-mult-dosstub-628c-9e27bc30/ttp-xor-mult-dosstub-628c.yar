rule TTP_XOR_MULT_DOSStub_628c {
  strings:
    $key_628c = { 36 e4 [2] 42 fc [2] 05 fe [2] 42 ef [2] 0c e3 [2] 00 e9 [2] 17 e2 [2] 0c ac [2] 31 }

  condition:
    any of them
}