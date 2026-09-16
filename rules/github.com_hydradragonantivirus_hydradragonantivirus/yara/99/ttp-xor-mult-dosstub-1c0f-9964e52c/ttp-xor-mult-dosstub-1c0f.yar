rule TTP_XOR_MULT_DOSStub_1c0f {
  strings:
    $key_1c0f = { 48 67 [2] 3c 7f [2] 7b 7d [2] 3c 6c [2] 72 60 [2] 7e 6a [2] 69 61 [2] 72 2f [2] 4f }

  condition:
    any of them
}