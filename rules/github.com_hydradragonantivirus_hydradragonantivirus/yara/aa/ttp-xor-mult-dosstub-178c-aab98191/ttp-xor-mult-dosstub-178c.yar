rule TTP_XOR_MULT_DOSStub_178c {
  strings:
    $key_178c = { 43 e4 [2] 37 fc [2] 70 fe [2] 37 ef [2] 79 e3 [2] 75 e9 [2] 62 e2 [2] 79 ac [2] 44 }

  condition:
    any of them
}