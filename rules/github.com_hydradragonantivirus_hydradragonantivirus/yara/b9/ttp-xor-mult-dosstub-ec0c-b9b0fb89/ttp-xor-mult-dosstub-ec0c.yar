rule TTP_XOR_MULT_DOSStub_ec0c {
  strings:
    $key_ec0c = { b8 64 [2] cc 7c [2] 8b 7e [2] cc 6f [2] 82 63 [2] 8e 69 [2] 99 62 [2] 82 2c [2] bf }

  condition:
    any of them
}