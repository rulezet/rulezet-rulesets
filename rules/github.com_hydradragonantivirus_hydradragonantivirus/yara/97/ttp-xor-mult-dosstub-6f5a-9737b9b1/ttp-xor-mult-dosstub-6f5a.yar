rule TTP_XOR_MULT_DOSStub_6f5a {
  strings:
    $key_6f5a = { 3b 32 [2] 4f 2a [2] 08 28 [2] 4f 39 [2] 01 35 [2] 0d 3f [2] 1a 34 [2] 01 7a [2] 3c }

  condition:
    any of them
}