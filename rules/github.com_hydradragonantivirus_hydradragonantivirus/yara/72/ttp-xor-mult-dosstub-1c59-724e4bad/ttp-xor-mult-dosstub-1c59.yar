rule TTP_XOR_MULT_DOSStub_1c59 {
  strings:
    $key_1c59 = { 48 31 [2] 3c 29 [2] 7b 2b [2] 3c 3a [2] 72 36 [2] 7e 3c [2] 69 37 [2] 72 79 [2] 4f }

  condition:
    any of them
}