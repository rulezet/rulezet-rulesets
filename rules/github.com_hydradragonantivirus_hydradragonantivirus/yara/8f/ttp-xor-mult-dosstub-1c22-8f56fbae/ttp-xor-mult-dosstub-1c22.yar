rule TTP_XOR_MULT_DOSStub_1c22 {
  strings:
    $key_1c22 = { 48 4a [2] 3c 52 [2] 7b 50 [2] 3c 41 [2] 72 4d [2] 7e 47 [2] 69 4c [2] 72 02 [2] 4f }

  condition:
    any of them
}