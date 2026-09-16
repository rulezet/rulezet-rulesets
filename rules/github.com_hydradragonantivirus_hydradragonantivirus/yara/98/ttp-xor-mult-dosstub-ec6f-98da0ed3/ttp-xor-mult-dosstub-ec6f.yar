rule TTP_XOR_MULT_DOSStub_ec6f {
  strings:
    $key_ec6f = { b8 07 [2] cc 1f [2] 8b 1d [2] cc 0c [2] 82 00 [2] 8e 0a [2] 99 01 [2] 82 4f [2] bf }

  condition:
    any of them
}