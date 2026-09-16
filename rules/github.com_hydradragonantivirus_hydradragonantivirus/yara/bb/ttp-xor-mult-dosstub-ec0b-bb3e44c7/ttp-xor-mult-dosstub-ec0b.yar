rule TTP_XOR_MULT_DOSStub_ec0b {
  strings:
    $key_ec0b = { b8 63 [2] cc 7b [2] 8b 79 [2] cc 68 [2] 82 64 [2] 8e 6e [2] 99 65 [2] 82 2b [2] bf }

  condition:
    any of them
}