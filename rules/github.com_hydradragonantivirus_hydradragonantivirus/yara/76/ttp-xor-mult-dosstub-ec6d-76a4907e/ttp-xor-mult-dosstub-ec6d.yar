rule TTP_XOR_MULT_DOSStub_ec6d {
  strings:
    $key_ec6d = { b8 05 [2] cc 1d [2] 8b 1f [2] cc 0e [2] 82 02 [2] 8e 08 [2] 99 03 [2] 82 4d [2] bf }

  condition:
    any of them
}