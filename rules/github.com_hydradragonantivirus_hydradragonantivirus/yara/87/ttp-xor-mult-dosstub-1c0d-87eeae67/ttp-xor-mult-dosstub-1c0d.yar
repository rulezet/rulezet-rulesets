rule TTP_XOR_MULT_DOSStub_1c0d {
  strings:
    $key_1c0d = { 48 65 [2] 3c 7d [2] 7b 7f [2] 3c 6e [2] 72 62 [2] 7e 68 [2] 69 63 [2] 72 2d [2] 4f }

  condition:
    any of them
}