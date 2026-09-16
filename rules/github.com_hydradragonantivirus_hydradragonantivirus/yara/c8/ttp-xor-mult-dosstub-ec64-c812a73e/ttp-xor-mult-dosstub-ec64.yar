rule TTP_XOR_MULT_DOSStub_ec64 {
  strings:
    $key_ec64 = { b8 0c [2] cc 14 [2] 8b 16 [2] cc 07 [2] 82 0b [2] 8e 01 [2] 99 0a [2] 82 44 [2] bf }

  condition:
    any of them
}