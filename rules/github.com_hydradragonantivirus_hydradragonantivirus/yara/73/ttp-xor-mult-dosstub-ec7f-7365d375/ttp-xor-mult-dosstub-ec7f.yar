rule TTP_XOR_MULT_DOSStub_ec7f {
  strings:
    $key_ec7f = { b8 17 [2] cc 0f [2] 8b 0d [2] cc 1c [2] 82 10 [2] 8e 1a [2] 99 11 [2] 82 5f [2] bf }

  condition:
    any of them
}