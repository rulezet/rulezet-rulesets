rule TTP_XOR_MULT_DOSStub_1c0b {
  strings:
    $key_1c0b = { 48 63 [2] 3c 7b [2] 7b 79 [2] 3c 68 [2] 72 64 [2] 7e 6e [2] 69 65 [2] 72 2b [2] 4f }

  condition:
    any of them
}