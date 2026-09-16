rule TTP_XOR_MULT_DOSStub_ec66 {
  strings:
    $key_ec66 = { b8 0e [2] cc 16 [2] 8b 14 [2] cc 05 [2] 82 09 [2] 8e 03 [2] 99 08 [2] 82 46 [2] bf }

  condition:
    any of them
}