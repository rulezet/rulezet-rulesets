rule TTP_XOR_MULT_DOSStub_ec38 {
  strings:
    $key_ec38 = { b8 50 [2] cc 48 [2] 8b 4a [2] cc 5b [2] 82 57 [2] 8e 5d [2] 99 56 [2] 82 18 [2] bf }

  condition:
    any of them
}