rule TTP_XOR_MULT_DOSStub_0f68 {
  strings:
    $key_0f68 = { 5b 00 [2] 2f 18 [2] 68 1a [2] 2f 0b [2] 61 07 [2] 6d 0d [2] 7a 06 [2] 61 48 [2] 5c }

  condition:
    any of them
}