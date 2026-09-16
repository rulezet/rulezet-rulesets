rule TTP_XOR_MULT_DOSStub_1c6f {
  strings:
    $key_1c6f = { 48 07 [2] 3c 1f [2] 7b 1d [2] 3c 0c [2] 72 00 [2] 7e 0a [2] 69 01 [2] 72 4f [2] 4f }

  condition:
    any of them
}