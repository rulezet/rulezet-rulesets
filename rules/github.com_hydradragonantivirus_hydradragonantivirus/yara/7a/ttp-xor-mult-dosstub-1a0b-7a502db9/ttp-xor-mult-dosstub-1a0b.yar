rule TTP_XOR_MULT_DOSStub_1a0b {
  strings:
    $key_1a0b = { 4e 63 [2] 3a 7b [2] 7d 79 [2] 3a 68 [2] 74 64 [2] 78 6e [2] 6f 65 [2] 74 2b [2] 49 }

  condition:
    any of them
}