rule TTP_XOR_MULT_DOSStub_ec62 {
  strings:
    $key_ec62 = { b8 0a [2] cc 12 [2] 8b 10 [2] cc 01 [2] 82 0d [2] 8e 07 [2] 99 0c [2] 82 42 [2] bf }

  condition:
    any of them
}