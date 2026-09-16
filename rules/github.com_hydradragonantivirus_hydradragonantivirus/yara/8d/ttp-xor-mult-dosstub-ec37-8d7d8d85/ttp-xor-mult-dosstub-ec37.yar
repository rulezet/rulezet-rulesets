rule TTP_XOR_MULT_DOSStub_ec37 {
  strings:
    $key_ec37 = { b8 5f [2] cc 47 [2] 8b 45 [2] cc 54 [2] 82 58 [2] 8e 52 [2] 99 59 [2] 82 17 [2] bf }

  condition:
    any of them
}