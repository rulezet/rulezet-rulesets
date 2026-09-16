rule TTP_XOR_MULT_DOSStub_ec79 {
  strings:
    $key_ec79 = { b8 11 [2] cc 09 [2] 8b 0b [2] cc 1a [2] 82 16 [2] 8e 1c [2] 99 17 [2] 82 59 [2] bf }

  condition:
    any of them
}