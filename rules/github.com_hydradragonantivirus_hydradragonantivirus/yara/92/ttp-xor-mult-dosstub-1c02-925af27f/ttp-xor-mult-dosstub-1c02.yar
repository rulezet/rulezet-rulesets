rule TTP_XOR_MULT_DOSStub_1c02 {
  strings:
    $key_1c02 = { 48 6a [2] 3c 72 [2] 7b 70 [2] 3c 61 [2] 72 6d [2] 7e 67 [2] 69 6c [2] 72 22 [2] 4f }

  condition:
    any of them
}