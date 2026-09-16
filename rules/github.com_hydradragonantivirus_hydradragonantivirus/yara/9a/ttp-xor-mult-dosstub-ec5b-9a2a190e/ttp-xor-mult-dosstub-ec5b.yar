rule TTP_XOR_MULT_DOSStub_ec5b {
  strings:
    $key_ec5b = { b8 33 [2] cc 2b [2] 8b 29 [2] cc 38 [2] 82 34 [2] 8e 3e [2] 99 35 [2] 82 7b [2] bf }

  condition:
    any of them
}