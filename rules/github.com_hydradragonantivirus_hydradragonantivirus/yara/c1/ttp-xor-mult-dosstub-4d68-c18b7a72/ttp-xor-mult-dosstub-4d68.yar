rule TTP_XOR_MULT_DOSStub_4d68 {
  strings:
    $key_4d68 = { 19 00 [2] 6d 18 [2] 2a 1a [2] 6d 0b [2] 23 07 [2] 2f 0d [2] 38 06 [2] 23 48 [2] 1e }

  condition:
    any of them
}