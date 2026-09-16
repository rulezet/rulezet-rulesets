rule TTP_XOR_MULT_DOSStub_1c5d {
  strings:
    $key_1c5d = { 48 35 [2] 3c 2d [2] 7b 2f [2] 3c 3e [2] 72 32 [2] 7e 38 [2] 69 33 [2] 72 7d [2] 4f }

  condition:
    any of them
}