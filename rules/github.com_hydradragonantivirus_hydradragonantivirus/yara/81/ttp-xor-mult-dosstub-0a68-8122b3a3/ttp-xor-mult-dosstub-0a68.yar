rule TTP_XOR_MULT_DOSStub_0a68 {
  strings:
    $key_0a68 = { 5e 00 [2] 2a 18 [2] 6d 1a [2] 2a 0b [2] 64 07 [2] 68 0d [2] 7f 06 [2] 64 48 [2] 59 }

  condition:
    any of them
}