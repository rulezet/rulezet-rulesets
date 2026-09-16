rule TTP_XOR_MULT_DOSStub_1cf2 {
  strings:
    $key_1cf2 = { 48 9a [2] 3c 82 [2] 7b 80 [2] 3c 91 [2] 72 9d [2] 7e 97 [2] 69 9c [2] 72 d2 [2] 4f }

  condition:
    any of them
}