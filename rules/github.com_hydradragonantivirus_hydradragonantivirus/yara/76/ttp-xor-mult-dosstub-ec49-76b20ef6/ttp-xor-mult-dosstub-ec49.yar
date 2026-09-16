rule TTP_XOR_MULT_DOSStub_ec49 {
  strings:
    $key_ec49 = { b8 21 [2] cc 39 [2] 8b 3b [2] cc 2a [2] 82 26 [2] 8e 2c [2] 99 27 [2] 82 69 [2] bf }

  condition:
    any of them
}