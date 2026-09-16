rule TTP_XOR_MULT_DOSStub_ec7e {
  strings:
    $key_ec7e = { b8 16 [2] cc 0e [2] 8b 0c [2] cc 1d [2] 82 11 [2] 8e 1b [2] 99 10 [2] 82 5e [2] bf }

  condition:
    any of them
}