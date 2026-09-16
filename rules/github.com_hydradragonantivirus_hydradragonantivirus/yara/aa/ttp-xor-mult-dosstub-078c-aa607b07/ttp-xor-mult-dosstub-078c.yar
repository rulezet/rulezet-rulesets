rule TTP_XOR_MULT_DOSStub_078c {
  strings:
    $key_078c = { 53 e4 [2] 27 fc [2] 60 fe [2] 27 ef [2] 69 e3 [2] 65 e9 [2] 72 e2 [2] 69 ac [2] 54 }

  condition:
    any of them
}