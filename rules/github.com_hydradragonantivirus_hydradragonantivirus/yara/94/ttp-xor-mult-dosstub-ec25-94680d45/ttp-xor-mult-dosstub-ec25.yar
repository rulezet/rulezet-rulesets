rule TTP_XOR_MULT_DOSStub_ec25 {
  strings:
    $key_ec25 = { b8 4d [2] cc 55 [2] 8b 57 [2] cc 46 [2] 82 4a [2] 8e 40 [2] 99 4b [2] 82 05 [2] bf }

  condition:
    any of them
}