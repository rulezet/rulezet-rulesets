rule TTP_XOR_MULT_DOSStub_ec21 {
  strings:
    $key_ec21 = { b8 49 [2] cc 51 [2] 8b 53 [2] cc 42 [2] 82 4e [2] 8e 44 [2] 99 4f [2] 82 01 [2] bf }

  condition:
    any of them
}