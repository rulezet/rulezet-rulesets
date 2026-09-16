rule TTP_XOR_MULT_DOSStub_ec5d {
  strings:
    $key_ec5d = { b8 35 [2] cc 2d [2] 8b 2f [2] cc 3e [2] 82 32 [2] 8e 38 [2] 99 33 [2] 82 7d [2] bf }

  condition:
    any of them
}