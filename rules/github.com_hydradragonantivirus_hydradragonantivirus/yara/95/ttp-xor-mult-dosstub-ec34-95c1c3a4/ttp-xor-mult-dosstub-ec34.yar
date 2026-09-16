rule TTP_XOR_MULT_DOSStub_ec34 {
  strings:
    $key_ec34 = { b8 5c [2] cc 44 [2] 8b 46 [2] cc 57 [2] 82 5b [2] 8e 51 [2] 99 5a [2] 82 14 [2] bf }

  condition:
    any of them
}