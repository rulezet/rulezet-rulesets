rule TTP_XOR_MULT_DOSStub_ec72 {
  strings:
    $key_ec72 = { b8 1a [2] cc 02 [2] 8b 00 [2] cc 11 [2] 82 1d [2] 8e 17 [2] 99 1c [2] 82 52 [2] bf }

  condition:
    any of them
}