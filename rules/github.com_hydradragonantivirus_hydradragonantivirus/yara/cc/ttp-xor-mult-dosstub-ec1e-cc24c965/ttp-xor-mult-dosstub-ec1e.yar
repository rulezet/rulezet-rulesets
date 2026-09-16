rule TTP_XOR_MULT_DOSStub_ec1e {
  strings:
    $key_ec1e = { b8 76 [2] cc 6e [2] 8b 6c [2] cc 7d [2] 82 71 [2] 8e 7b [2] 99 70 [2] 82 3e [2] bf }

  condition:
    any of them
}