rule TTP_XOR_MULT_DOSStub_5d0b {
  strings:
    $key_5d0b = { 09 63 [2] 7d 7b [2] 3a 79 [2] 7d 68 [2] 33 64 [2] 3f 6e [2] 28 65 [2] 33 2b [2] 0e }

  condition:
    any of them
}