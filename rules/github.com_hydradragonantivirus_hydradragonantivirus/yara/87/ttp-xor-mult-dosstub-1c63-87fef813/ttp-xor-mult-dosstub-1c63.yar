rule TTP_XOR_MULT_DOSStub_1c63 {
  strings:
    $key_1c63 = { 48 0b [2] 3c 13 [2] 7b 11 [2] 3c 00 [2] 72 0c [2] 7e 06 [2] 69 0d [2] 72 43 [2] 4f }

  condition:
    any of them
}