rule TTP_XOR_MULT_DOSStub_7d0b {
  strings:
    $key_7d0b = { 29 63 [2] 5d 7b [2] 1a 79 [2] 5d 68 [2] 13 64 [2] 1f 6e [2] 08 65 [2] 13 2b [2] 2e }

  condition:
    any of them
}