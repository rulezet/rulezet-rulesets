rule TTP_XOR_MULT_DOSStub_780b {
  strings:
    $key_780b = { 2c 63 [2] 58 7b [2] 1f 79 [2] 58 68 [2] 16 64 [2] 1a 6e [2] 0d 65 [2] 16 2b [2] 2b }

  condition:
    any of them
}