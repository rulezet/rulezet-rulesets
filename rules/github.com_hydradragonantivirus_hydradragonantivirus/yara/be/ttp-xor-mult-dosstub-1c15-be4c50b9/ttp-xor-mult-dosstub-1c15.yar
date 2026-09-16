rule TTP_XOR_MULT_DOSStub_1c15 {
  strings:
    $key_1c15 = { 48 7d [2] 3c 65 [2] 7b 67 [2] 3c 76 [2] 72 7a [2] 7e 70 [2] 69 7b [2] 72 35 [2] 4f }

  condition:
    any of them
}