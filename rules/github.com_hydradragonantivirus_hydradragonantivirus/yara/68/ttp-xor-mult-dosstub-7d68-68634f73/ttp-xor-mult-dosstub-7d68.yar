rule TTP_XOR_MULT_DOSStub_7d68 {
  strings:
    $key_7d68 = { 29 00 [2] 5d 18 [2] 1a 1a [2] 5d 0b [2] 13 07 [2] 1f 0d [2] 08 06 [2] 13 48 [2] 2e }

  condition:
    any of them
}