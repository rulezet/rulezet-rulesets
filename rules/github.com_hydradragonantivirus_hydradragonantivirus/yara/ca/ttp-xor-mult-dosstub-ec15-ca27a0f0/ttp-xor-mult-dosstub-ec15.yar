rule TTP_XOR_MULT_DOSStub_ec15 {
  strings:
    $key_ec15 = { b8 7d [2] cc 65 [2] 8b 67 [2] cc 76 [2] 82 7a [2] 8e 70 [2] 99 7b [2] 82 35 [2] bf }

  condition:
    any of them
}