rule TTP_XOR_MULT_DOSStub_4465 {
  strings:
    $key_4465 = { 10 0d [2] 64 15 [2] 23 17 [2] 64 06 [2] 2a 0a [2] 26 00 [2] 31 0b [2] 2a 45 [2] 17 }

  condition:
    any of them
}