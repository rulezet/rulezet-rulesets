rule TTP_XOR_MULT_DOSStub_6c8c {
  strings:
    $key_6c8c = { 38 e4 [2] 4c fc [2] 0b fe [2] 4c ef [2] 02 e3 [2] 0e e9 [2] 19 e2 [2] 02 ac [2] 3f }

  condition:
    any of them
}