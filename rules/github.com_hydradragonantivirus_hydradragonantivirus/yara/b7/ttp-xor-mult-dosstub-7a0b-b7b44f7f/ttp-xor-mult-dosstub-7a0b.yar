rule TTP_XOR_MULT_DOSStub_7a0b {
  strings:
    $key_7a0b = { 2e 63 [2] 5a 7b [2] 1d 79 [2] 5a 68 [2] 14 64 [2] 18 6e [2] 0f 65 [2] 14 2b [2] 29 }

  condition:
    any of them
}