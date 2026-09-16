rule TTP_XOR_MULT_DOSStub_db9b {
  strings:
    $key_db9b = { 8f f3 [2] fb eb [2] bc e9 [2] fb f8 [2] b5 f4 [2] b9 fe [2] ae f5 [2] b5 bb [2] 88 }

  condition:
    any of them
}