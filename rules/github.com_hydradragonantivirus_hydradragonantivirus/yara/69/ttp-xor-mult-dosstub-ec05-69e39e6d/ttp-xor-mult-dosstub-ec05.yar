rule TTP_XOR_MULT_DOSStub_ec05 {
  strings:
    $key_ec05 = { b8 6d [2] cc 75 [2] 8b 77 [2] cc 66 [2] 82 6a [2] 8e 60 [2] 99 6b [2] 82 25 [2] bf }

  condition:
    any of them
}