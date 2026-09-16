rule TTP_XOR_MULT_DOSStub_ec32 {
  strings:
    $key_ec32 = { b8 5a [2] cc 42 [2] 8b 40 [2] cc 51 [2] 82 5d [2] 8e 57 [2] 99 5c [2] 82 12 [2] bf }

  condition:
    any of them
}