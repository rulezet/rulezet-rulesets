rule TTP_XOR_MULT_DOSStub_ec71 {
  strings:
    $key_ec71 = { b8 19 [2] cc 01 [2] 8b 03 [2] cc 12 [2] 82 1e [2] 8e 14 [2] 99 1f [2] 82 51 [2] bf }

  condition:
    any of them
}