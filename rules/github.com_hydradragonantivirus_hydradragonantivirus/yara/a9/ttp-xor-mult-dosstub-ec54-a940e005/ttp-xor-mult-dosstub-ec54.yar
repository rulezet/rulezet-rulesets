rule TTP_XOR_MULT_DOSStub_ec54 {
  strings:
    $key_ec54 = { b8 3c [2] cc 24 [2] 8b 26 [2] cc 37 [2] 82 3b [2] 8e 31 [2] 99 3a [2] 82 74 [2] bf }

  condition:
    any of them
}