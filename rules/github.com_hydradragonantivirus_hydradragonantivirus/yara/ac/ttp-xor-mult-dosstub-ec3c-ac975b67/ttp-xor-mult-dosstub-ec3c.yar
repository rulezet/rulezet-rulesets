rule TTP_XOR_MULT_DOSStub_ec3c {
  strings:
    $key_ec3c = { b8 54 [2] cc 4c [2] 8b 4e [2] cc 5f [2] 82 53 [2] 8e 59 [2] 99 52 [2] 82 1c [2] bf }

  condition:
    any of them
}