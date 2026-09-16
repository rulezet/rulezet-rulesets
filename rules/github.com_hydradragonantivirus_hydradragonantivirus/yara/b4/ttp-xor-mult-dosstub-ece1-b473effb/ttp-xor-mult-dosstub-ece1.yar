rule TTP_XOR_MULT_DOSStub_ece1 {
  strings:
    $key_ece1 = { b8 89 [2] cc 91 [2] 8b 93 [2] cc 82 [2] 82 8e [2] 8e 84 [2] 99 8f [2] 82 c1 [2] bf }

  condition:
    any of them
}