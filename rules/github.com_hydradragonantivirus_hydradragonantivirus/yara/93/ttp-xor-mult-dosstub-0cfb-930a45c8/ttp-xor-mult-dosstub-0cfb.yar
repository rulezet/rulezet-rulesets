rule TTP_XOR_MULT_DOSStub_0cfb {
  strings:
    $key_0cfb = { 58 93 [2] 2c 8b [2] 6b 89 [2] 2c 98 [2] 62 94 [2] 6e 9e [2] 79 95 [2] 62 db [2] 5f }

  condition:
    any of them
}