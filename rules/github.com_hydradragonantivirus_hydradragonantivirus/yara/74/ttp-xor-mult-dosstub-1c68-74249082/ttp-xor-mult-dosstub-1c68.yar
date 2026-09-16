rule TTP_XOR_MULT_DOSStub_1c68 {
  strings:
    $key_1c68 = { 48 00 [2] 3c 18 [2] 7b 1a [2] 3c 0b [2] 72 07 [2] 7e 0d [2] 69 06 [2] 72 48 [2] 4f }

  condition:
    any of them
}