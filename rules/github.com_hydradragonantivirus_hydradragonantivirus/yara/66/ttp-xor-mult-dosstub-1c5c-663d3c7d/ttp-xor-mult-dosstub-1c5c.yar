rule TTP_XOR_MULT_DOSStub_1c5c {
  strings:
    $key_1c5c = { 48 34 [2] 3c 2c [2] 7b 2e [2] 3c 3f [2] 72 33 [2] 7e 39 [2] 69 32 [2] 72 7c [2] 4f }

  condition:
    any of them
}