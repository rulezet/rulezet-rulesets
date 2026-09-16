rule TTP_XOR_MULT_DOSStub_ec0a {
  strings:
    $key_ec0a = { b8 62 [2] cc 7a [2] 8b 78 [2] cc 69 [2] 82 65 [2] 8e 6f [2] 99 64 [2] 82 2a [2] bf }

  condition:
    any of them
}