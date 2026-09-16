rule TTP_XOR_MULT_DOSStub_1cf4 {
  strings:
    $key_1cf4 = { 48 9c [2] 3c 84 [2] 7b 86 [2] 3c 97 [2] 72 9b [2] 7e 91 [2] 69 9a [2] 72 d4 [2] 4f }

  condition:
    any of them
}