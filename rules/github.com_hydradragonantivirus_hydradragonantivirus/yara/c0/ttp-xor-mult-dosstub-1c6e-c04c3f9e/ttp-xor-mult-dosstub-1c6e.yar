rule TTP_XOR_MULT_DOSStub_1c6e {
  strings:
    $key_1c6e = { 48 06 [2] 3c 1e [2] 7b 1c [2] 3c 0d [2] 72 01 [2] 7e 0b [2] 69 00 [2] 72 4e [2] 4f }

  condition:
    any of them
}