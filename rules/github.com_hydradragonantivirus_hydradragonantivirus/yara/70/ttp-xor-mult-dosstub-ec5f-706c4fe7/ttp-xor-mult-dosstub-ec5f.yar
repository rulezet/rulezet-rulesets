rule TTP_XOR_MULT_DOSStub_ec5f {
  strings:
    $key_ec5f = { b8 37 [2] cc 2f [2] 8b 2d [2] cc 3c [2] 82 30 [2] 8e 3a [2] 99 31 [2] 82 7f [2] bf }

  condition:
    any of them
}