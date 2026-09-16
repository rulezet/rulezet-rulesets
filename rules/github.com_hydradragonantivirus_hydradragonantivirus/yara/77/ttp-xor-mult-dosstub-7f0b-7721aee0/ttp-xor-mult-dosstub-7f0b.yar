rule TTP_XOR_MULT_DOSStub_7f0b {
  strings:
    $key_7f0b = { 2b 63 [2] 5f 7b [2] 18 79 [2] 5f 68 [2] 11 64 [2] 1d 6e [2] 0a 65 [2] 11 2b [2] 2c }

  condition:
    any of them
}