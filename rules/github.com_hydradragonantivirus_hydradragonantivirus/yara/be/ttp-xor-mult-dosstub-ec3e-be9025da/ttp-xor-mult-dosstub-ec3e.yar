rule TTP_XOR_MULT_DOSStub_ec3e {
  strings:
    $key_ec3e = { b8 56 [2] cc 4e [2] 8b 4c [2] cc 5d [2] 82 51 [2] 8e 5b [2] 99 50 [2] 82 1e [2] bf }

  condition:
    any of them
}