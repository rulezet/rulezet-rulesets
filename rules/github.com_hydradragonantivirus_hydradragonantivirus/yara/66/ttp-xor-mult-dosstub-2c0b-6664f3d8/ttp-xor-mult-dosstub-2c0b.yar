rule TTP_XOR_MULT_DOSStub_2c0b {
  strings:
    $key_2c0b = { 78 63 [2] 0c 7b [2] 4b 79 [2] 0c 68 [2] 42 64 [2] 4e 6e [2] 59 65 [2] 42 2b [2] 7f }

  condition:
    any of them
}