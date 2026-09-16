rule TTP_XOR_MULT_DOSStub_1c5f {
  strings:
    $key_1c5f = { 48 37 [2] 3c 2f [2] 7b 2d [2] 3c 3c [2] 72 30 [2] 7e 3a [2] 69 31 [2] 72 7f [2] 4f }

  condition:
    any of them
}