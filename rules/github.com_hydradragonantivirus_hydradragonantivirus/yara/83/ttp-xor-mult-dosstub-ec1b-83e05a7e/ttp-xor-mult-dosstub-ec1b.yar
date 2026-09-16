rule TTP_XOR_MULT_DOSStub_ec1b {
  strings:
    $key_ec1b = { b8 73 [2] cc 6b [2] 8b 69 [2] cc 78 [2] 82 74 [2] 8e 7e [2] 99 75 [2] 82 3b [2] bf }

  condition:
    any of them
}