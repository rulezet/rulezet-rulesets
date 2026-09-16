rule TTP_XOR_MULT_DOSStub_7a65 {
  strings:
    $key_7a65 = { 2e 0d [2] 5a 15 [2] 1d 17 [2] 5a 06 [2] 14 0a [2] 18 00 [2] 0f 0b [2] 14 45 [2] 29 }

  condition:
    any of them
}