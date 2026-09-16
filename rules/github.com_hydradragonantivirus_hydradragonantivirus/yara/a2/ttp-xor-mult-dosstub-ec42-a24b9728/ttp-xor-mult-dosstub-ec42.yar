rule TTP_XOR_MULT_DOSStub_ec42 {
  strings:
    $key_ec42 = { b8 2a [2] cc 32 [2] 8b 30 [2] cc 21 [2] 82 2d [2] 8e 27 [2] 99 2c [2] 82 62 [2] bf }

  condition:
    any of them
}