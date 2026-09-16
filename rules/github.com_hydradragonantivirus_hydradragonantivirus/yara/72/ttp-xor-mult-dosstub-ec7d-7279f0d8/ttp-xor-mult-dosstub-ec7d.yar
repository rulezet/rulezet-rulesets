rule TTP_XOR_MULT_DOSStub_ec7d {
  strings:
    $key_ec7d = { b8 15 [2] cc 0d [2] 8b 0f [2] cc 1e [2] 82 12 [2] 8e 18 [2] 99 13 [2] 82 5d [2] bf }

  condition:
    any of them
}