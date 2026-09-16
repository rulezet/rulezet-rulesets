rule TTP_XOR_MULT_DOSStub_770b {
  strings:
    $key_770b = { 23 63 [2] 57 7b [2] 10 79 [2] 57 68 [2] 19 64 [2] 15 6e [2] 02 65 [2] 19 2b [2] 24 }

  condition:
    any of them
}