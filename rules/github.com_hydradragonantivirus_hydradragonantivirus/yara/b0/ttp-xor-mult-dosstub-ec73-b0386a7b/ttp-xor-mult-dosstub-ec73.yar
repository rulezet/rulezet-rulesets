rule TTP_XOR_MULT_DOSStub_ec73 {
  strings:
    $key_ec73 = { b8 1b [2] cc 03 [2] 8b 01 [2] cc 10 [2] 82 1c [2] 8e 16 [2] 99 1d [2] 82 53 [2] bf }

  condition:
    any of them
}