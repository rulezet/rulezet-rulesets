rule TTP_XOR_MULT_DOSStub_1c6d {
  strings:
    $key_1c6d = { 48 05 [2] 3c 1d [2] 7b 1f [2] 3c 0e [2] 72 02 [2] 7e 08 [2] 69 03 [2] 72 4d [2] 4f }

  condition:
    any of them
}