rule TTP_XOR_MULT_DOSStub_ec13 {
  strings:
    $key_ec13 = { b8 7b [2] cc 63 [2] 8b 61 [2] cc 70 [2] 82 7c [2] 8e 76 [2] 99 7d [2] 82 33 [2] bf }

  condition:
    any of them
}