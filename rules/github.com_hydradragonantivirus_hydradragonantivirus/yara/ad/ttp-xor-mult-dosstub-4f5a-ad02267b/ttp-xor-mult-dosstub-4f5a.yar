rule TTP_XOR_MULT_DOSStub_4f5a {
  strings:
    $key_4f5a = { 1b 32 [2] 6f 2a [2] 28 28 [2] 6f 39 [2] 21 35 [2] 2d 3f [2] 3a 34 [2] 21 7a [2] 1c }

  condition:
    any of them
}