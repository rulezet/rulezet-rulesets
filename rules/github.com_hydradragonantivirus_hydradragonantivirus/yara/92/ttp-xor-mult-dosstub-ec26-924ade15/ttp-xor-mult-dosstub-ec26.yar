rule TTP_XOR_MULT_DOSStub_ec26 {
  strings:
    $key_ec26 = { b8 4e [2] cc 56 [2] 8b 54 [2] cc 45 [2] 82 49 [2] 8e 43 [2] 99 48 [2] 82 06 [2] bf }

  condition:
    any of them
}