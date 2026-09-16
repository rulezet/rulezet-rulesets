rule TTP_XOR_MULT_DOSStub_0f72 {
  strings:
    $key_0f72 = { 5b 1a [2] 2f 02 [2] 68 00 [2] 2f 11 [2] 61 1d [2] 6d 17 [2] 7a 1c [2] 61 52 [2] 5c }

  condition:
    any of them
}