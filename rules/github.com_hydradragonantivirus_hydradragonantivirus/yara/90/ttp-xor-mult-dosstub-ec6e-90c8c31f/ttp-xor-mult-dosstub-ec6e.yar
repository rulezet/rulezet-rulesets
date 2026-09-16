rule TTP_XOR_MULT_DOSStub_ec6e {
  strings:
    $key_ec6e = { b8 06 [2] cc 1e [2] 8b 1c [2] cc 0d [2] 82 01 [2] 8e 0b [2] 99 00 [2] 82 4e [2] bf }

  condition:
    any of them
}