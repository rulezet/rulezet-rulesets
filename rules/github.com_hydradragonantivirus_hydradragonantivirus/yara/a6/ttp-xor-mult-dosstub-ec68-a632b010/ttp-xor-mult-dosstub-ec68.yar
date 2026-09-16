rule TTP_XOR_MULT_DOSStub_ec68 {
  strings:
    $key_ec68 = { b8 00 [2] cc 18 [2] 8b 1a [2] cc 0b [2] 82 07 [2] 8e 0d [2] 99 06 [2] 82 48 [2] bf }

  condition:
    any of them
}