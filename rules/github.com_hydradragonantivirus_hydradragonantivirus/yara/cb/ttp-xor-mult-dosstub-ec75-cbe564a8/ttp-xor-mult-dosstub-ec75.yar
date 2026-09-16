rule TTP_XOR_MULT_DOSStub_ec75 {
  strings:
    $key_ec75 = { b8 1d [2] cc 05 [2] 8b 07 [2] cc 16 [2] 82 1a [2] 8e 10 [2] 99 1b [2] 82 55 [2] bf }

  condition:
    any of them
}