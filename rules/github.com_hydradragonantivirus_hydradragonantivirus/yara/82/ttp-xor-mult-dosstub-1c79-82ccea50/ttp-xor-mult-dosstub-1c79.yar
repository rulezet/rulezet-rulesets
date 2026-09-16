rule TTP_XOR_MULT_DOSStub_1c79 {
  strings:
    $key_1c79 = { 48 11 [2] 3c 09 [2] 7b 0b [2] 3c 1a [2] 72 16 [2] 7e 1c [2] 69 17 [2] 72 59 [2] 4f }

  condition:
    any of them
}