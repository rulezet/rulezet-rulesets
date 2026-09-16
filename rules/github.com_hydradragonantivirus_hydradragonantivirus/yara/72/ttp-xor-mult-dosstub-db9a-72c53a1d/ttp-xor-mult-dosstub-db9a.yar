rule TTP_XOR_MULT_DOSStub_db9a {
  strings:
    $key_db9a = { 8f f2 [2] fb ea [2] bc e8 [2] fb f9 [2] b5 f5 [2] b9 ff [2] ae f4 [2] b5 ba [2] 88 }

  condition:
    any of them
}