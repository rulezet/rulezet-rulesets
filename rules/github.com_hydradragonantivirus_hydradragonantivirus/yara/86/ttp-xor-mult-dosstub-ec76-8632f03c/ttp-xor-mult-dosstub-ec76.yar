rule TTP_XOR_MULT_DOSStub_ec76 {
  strings:
    $key_ec76 = { b8 1e [2] cc 06 [2] 8b 04 [2] cc 15 [2] 82 19 [2] 8e 13 [2] 99 18 [2] 82 56 [2] bf }

  condition:
    any of them
}