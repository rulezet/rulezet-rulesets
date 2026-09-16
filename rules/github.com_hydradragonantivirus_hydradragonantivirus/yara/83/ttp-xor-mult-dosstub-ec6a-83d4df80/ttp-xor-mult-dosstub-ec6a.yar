rule TTP_XOR_MULT_DOSStub_ec6a {
  strings:
    $key_ec6a = { b8 02 [2] cc 1a [2] 8b 18 [2] cc 09 [2] 82 05 [2] 8e 0f [2] 99 04 [2] 82 4a [2] bf }

  condition:
    any of them
}