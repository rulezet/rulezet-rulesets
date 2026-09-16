rule TTP_XOR_MULT_DOSStub_ec56 {
  strings:
    $key_ec56 = { b8 3e [2] cc 26 [2] 8b 24 [2] cc 35 [2] 82 39 [2] 8e 33 [2] 99 38 [2] 82 76 [2] bf }

  condition:
    any of them
}