rule TTP_XOR_MULT_DOSStub_ec0e {
  strings:
    $key_ec0e = { b8 66 [2] cc 7e [2] 8b 7c [2] cc 6d [2] 82 61 [2] 8e 6b [2] 99 60 [2] 82 2e [2] bf }

  condition:
    any of them
}