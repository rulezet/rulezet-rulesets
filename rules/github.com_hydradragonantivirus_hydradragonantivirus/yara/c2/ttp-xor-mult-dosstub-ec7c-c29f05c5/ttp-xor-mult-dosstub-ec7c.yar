rule TTP_XOR_MULT_DOSStub_ec7c {
  strings:
    $key_ec7c = { b8 14 [2] cc 0c [2] 8b 0e [2] cc 1f [2] 82 13 [2] 8e 19 [2] 99 12 [2] 82 5c [2] bf }

  condition:
    any of them
}