rule TTP_XOR_MULT_DOSStub_ec67 {
  strings:
    $key_ec67 = { b8 0f [2] cc 17 [2] 8b 15 [2] cc 04 [2] 82 08 [2] 8e 02 [2] 99 09 [2] 82 47 [2] bf }

  condition:
    any of them
}