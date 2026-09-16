rule TTP_XOR_MULT_DOSStub_4168 {
  strings:
    $key_4168 = { 15 00 [2] 61 18 [2] 26 1a [2] 61 0b [2] 2f 07 [2] 23 0d [2] 34 06 [2] 2f 48 [2] 12 }

  condition:
    any of them
}