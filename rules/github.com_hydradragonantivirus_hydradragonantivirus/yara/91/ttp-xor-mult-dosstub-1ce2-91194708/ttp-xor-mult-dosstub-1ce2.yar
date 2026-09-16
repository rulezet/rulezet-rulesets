rule TTP_XOR_MULT_DOSStub_1ce2 {
  strings:
    $key_1ce2 = { 48 8a [2] 3c 92 [2] 7b 90 [2] 3c 81 [2] 72 8d [2] 7e 87 [2] 69 8c [2] 72 c2 [2] 4f }

  condition:
    any of them
}