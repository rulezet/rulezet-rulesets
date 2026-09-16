rule TTP_XOR_MULT_DOSStub_ec3b {
  strings:
    $key_ec3b = { b8 53 [2] cc 4b [2] 8b 49 [2] cc 58 [2] 82 54 [2] 8e 5e [2] 99 55 [2] 82 1b [2] bf }

  condition:
    any of them
}