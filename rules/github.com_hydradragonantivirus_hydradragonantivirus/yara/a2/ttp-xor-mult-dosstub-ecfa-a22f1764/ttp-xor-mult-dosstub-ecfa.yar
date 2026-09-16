rule TTP_XOR_MULT_DOSStub_ecfa {
  strings:
    $key_ecfa = { b8 92 [2] cc 8a [2] 8b 88 [2] cc 99 [2] 82 95 [2] 8e 9f [2] 99 94 [2] 82 da [2] bf }

  condition:
    any of them
}