rule TTP_XOR_MULT_DOSStub_ec07 {
  strings:
    $key_ec07 = { b8 6f [2] cc 77 [2] 8b 75 [2] cc 64 [2] 82 68 [2] 8e 62 [2] 99 69 [2] 82 27 [2] bf }

  condition:
    any of them
}