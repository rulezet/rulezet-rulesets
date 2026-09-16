rule TTP_XOR_MULT_DOSStub_038c {
  strings:
    $key_038c = { 57 e4 [2] 23 fc [2] 64 fe [2] 23 ef [2] 6d e3 [2] 61 e9 [2] 76 e2 [2] 6d ac [2] 50 }

  condition:
    any of them
}