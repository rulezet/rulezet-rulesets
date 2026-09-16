rule TTP_XOR_MULT_DOSStub_1c7f {
  strings:
    $key_1c7f = { 48 17 [2] 3c 0f [2] 7b 0d [2] 3c 1c [2] 72 10 [2] 7e 1a [2] 69 11 [2] 72 5f [2] 4f }

  condition:
    any of them
}