rule TTP_XOR_MULT_DOSStub_2a68 {
  strings:
    $key_2a68 = { 7e 00 [2] 0a 18 [2] 4d 1a [2] 0a 0b [2] 44 07 [2] 48 0d [2] 5f 06 [2] 44 48 [2] 79 }

  condition:
    any of them
}