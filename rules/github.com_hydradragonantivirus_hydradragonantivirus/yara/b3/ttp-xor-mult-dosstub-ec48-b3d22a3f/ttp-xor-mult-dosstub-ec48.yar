rule TTP_XOR_MULT_DOSStub_ec48 {
  strings:
    $key_ec48 = { b8 20 [2] cc 38 [2] 8b 3a [2] cc 2b [2] 82 27 [2] 8e 2d [2] 99 26 [2] 82 68 [2] bf }

  condition:
    any of them
}