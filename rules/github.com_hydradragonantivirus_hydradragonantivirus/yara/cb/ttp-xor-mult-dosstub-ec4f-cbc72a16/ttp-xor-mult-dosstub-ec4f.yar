rule TTP_XOR_MULT_DOSStub_ec4f {
  strings:
    $key_ec4f = { b8 27 [2] cc 3f [2] 8b 3d [2] cc 2c [2] 82 20 [2] 8e 2a [2] 99 21 [2] 82 6f [2] bf }

  condition:
    any of them
}