rule TTP_XOR_MULT_DOSStub_db8c {
  strings:
    $key_db8c = { 8f e4 [2] fb fc [2] bc fe [2] fb ef [2] b5 e3 [2] b9 e9 [2] ae e2 [2] b5 ac [2] 88 }

  condition:
    any of them
}