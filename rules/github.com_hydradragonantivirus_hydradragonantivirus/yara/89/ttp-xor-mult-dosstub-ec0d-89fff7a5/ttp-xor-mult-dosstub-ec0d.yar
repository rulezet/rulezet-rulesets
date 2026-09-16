rule TTP_XOR_MULT_DOSStub_ec0d {
  strings:
    $key_ec0d = { b8 65 [2] cc 7d [2] 8b 7f [2] cc 6e [2] 82 62 [2] 8e 68 [2] 99 63 [2] 82 2d [2] bf }

  condition:
    any of them
}