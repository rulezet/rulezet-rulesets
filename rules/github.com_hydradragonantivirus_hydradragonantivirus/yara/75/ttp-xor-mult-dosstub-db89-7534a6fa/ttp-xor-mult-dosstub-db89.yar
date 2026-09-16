rule TTP_XOR_MULT_DOSStub_db89 {
  strings:
    $key_db89 = { 8f e1 [2] fb f9 [2] bc fb [2] fb ea [2] b5 e6 [2] b9 ec [2] ae e7 [2] b5 a9 [2] 88 }

  condition:
    any of them
}