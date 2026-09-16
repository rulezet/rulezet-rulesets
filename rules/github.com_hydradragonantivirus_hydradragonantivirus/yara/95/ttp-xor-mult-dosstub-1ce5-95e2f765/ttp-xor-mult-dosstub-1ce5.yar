rule TTP_XOR_MULT_DOSStub_1ce5 {
  strings:
    $key_1ce5 = { 48 8d [2] 3c 95 [2] 7b 97 [2] 3c 86 [2] 72 8a [2] 7e 80 [2] 69 8b [2] 72 c5 [2] 4f }

  condition:
    any of them
}