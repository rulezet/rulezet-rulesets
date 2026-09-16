rule TTP_XOR_MULT_DOSStub_7b68 {
  strings:
    $key_7b68 = { 2f 00 [2] 5b 18 [2] 1c 1a [2] 5b 0b [2] 15 07 [2] 19 0d [2] 0e 06 [2] 15 48 [2] 28 }

  condition:
    any of them
}