rule TTP_XOR_MULT_DOSStub_ec14 {
  strings:
    $key_ec14 = { b8 7c [2] cc 64 [2] 8b 66 [2] cc 77 [2] 82 7b [2] 8e 71 [2] 99 7a [2] 82 34 [2] bf }

  condition:
    any of them
}