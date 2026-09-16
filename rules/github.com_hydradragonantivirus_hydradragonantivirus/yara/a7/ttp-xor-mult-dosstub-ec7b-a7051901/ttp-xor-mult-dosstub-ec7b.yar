rule TTP_XOR_MULT_DOSStub_ec7b {
  strings:
    $key_ec7b = { b8 13 [2] cc 0b [2] 8b 09 [2] cc 18 [2] 82 14 [2] 8e 1e [2] 99 15 [2] 82 5b [2] bf }

  condition:
    any of them
}