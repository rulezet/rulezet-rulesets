rule TTP_XOR_MULT_DOSStub_ec1f {
  strings:
    $key_ec1f = { b8 77 [2] cc 6f [2] 8b 6d [2] cc 7c [2] 82 70 [2] 8e 7a [2] 99 71 [2] 82 3f [2] bf }

  condition:
    any of them
}