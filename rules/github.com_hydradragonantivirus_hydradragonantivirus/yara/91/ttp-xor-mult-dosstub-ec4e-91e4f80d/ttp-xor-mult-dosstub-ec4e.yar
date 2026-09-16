rule TTP_XOR_MULT_DOSStub_ec4e {
  strings:
    $key_ec4e = { b8 26 [2] cc 3e [2] 8b 3c [2] cc 2d [2] 82 21 [2] 8e 2b [2] 99 20 [2] 82 6e [2] bf }

  condition:
    any of them
}