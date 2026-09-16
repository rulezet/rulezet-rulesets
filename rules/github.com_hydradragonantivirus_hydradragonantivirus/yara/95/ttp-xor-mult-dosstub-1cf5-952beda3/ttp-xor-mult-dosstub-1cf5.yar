rule TTP_XOR_MULT_DOSStub_1cf5 {
  strings:
    $key_1cf5 = { 48 9d [2] 3c 85 [2] 7b 87 [2] 3c 96 [2] 72 9a [2] 7e 90 [2] 69 9b [2] 72 d5 [2] 4f }

  condition:
    any of them
}