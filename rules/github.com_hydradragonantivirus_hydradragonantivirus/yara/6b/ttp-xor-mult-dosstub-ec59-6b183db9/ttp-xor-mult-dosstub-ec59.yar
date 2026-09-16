rule TTP_XOR_MULT_DOSStub_ec59 {
  strings:
    $key_ec59 = { b8 31 [2] cc 29 [2] 8b 2b [2] cc 3a [2] 82 36 [2] 8e 3c [2] 99 37 [2] 82 79 [2] bf }

  condition:
    any of them
}