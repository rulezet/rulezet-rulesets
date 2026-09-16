rule TTP_XOR_MULT_DOSStub_0b68 {
  strings:
    $key_0b68 = { 5f 00 [2] 2b 18 [2] 6c 1a [2] 2b 0b [2] 65 07 [2] 69 0d [2] 7e 06 [2] 65 48 [2] 58 }

  condition:
    any of them
}