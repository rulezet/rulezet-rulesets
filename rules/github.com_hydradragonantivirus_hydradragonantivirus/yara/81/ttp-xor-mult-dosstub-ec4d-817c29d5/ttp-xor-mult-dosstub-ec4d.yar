rule TTP_XOR_MULT_DOSStub_ec4d {
  strings:
    $key_ec4d = { b8 25 [2] cc 3d [2] 8b 3f [2] cc 2e [2] 82 22 [2] 8e 28 [2] 99 23 [2] 82 6d [2] bf }

  condition:
    any of them
}